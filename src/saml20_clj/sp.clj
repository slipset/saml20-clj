(ns saml20-clj.sp
  (:require [clj-time
             [coerce :refer [to-timestamp]]
             [core :as ctime]]
            [clojure
             [string :as str]
             [xml :refer [parse]]
             [zip :as zip]]
            [clojure.data.zip.xml :as zf]
            [clojure.tools.logging :as log]
            [hiccup
             [core :as hiccup]
             [page :as h.page]]
            [saml20-clj
             [shared :as shared]
             [xml :as saml-xml]])
  (:import javax.xml.crypto.dsig.XMLSignature
           org.apache.xml.security.c14n.Canonicalizer
           org.apache.xml.security.Init
           org.apache.xml.security.transforms.Transforms
           [org.apache.xml.security.utils Constants ElementProxy]
           [org.opensaml.saml2.core Assertion Attribute AttributeStatement Audience AudienceRestriction
            EncryptedAssertion Response SubjectConfirmation]
           org.opensaml.saml2.encryption.Decrypter))

;;; These next 3 fns are defaults for storing SAML state in memory.
(defn bump-saml-id-timeout!
  "Sets the current time to the provided saml-id in the saml-id-timeouts ref map.
  This function has side-effects."
  [saml-id-timeouts saml-id issue-instant]
  (dosync (alter saml-id-timeouts assoc saml-id issue-instant)))

(defn next-saml-id!
  "Returns the next available saml id."
  [saml-last-id]
  (swap! saml-last-id inc))

(defn prune-timed-out-ids!
  "Given a timeout duration, remove all SAML IDs that are older than now minus the timeout."
  [saml-id-timeouts timeout-duration]
  (let [filter-fn
        (partial filter (shared/make-timeout-filter-fn timeout-duration))]
    (dosync
      (ref-set saml-id-timeouts (into {} (filter-fn @saml-id-timeouts))))))

(defn metadata [app-name acs-uri certificate-str]
  (str
   (h.page/xml-declaration "UTF-8")
   (hiccup/html
    [:md:EntityDescriptor {:xmlns:md "urn:oasis:names:tc:SAML:2.0:metadata"
                           :ID       (str/replace acs-uri #"[:/]" "_")
                           :entityID app-name}
     [:md:SPSSODescriptor {:AuthnRequestsSigned        "true"
                           :WantAssertionsSigned       "true"
                           :protocolSupportEnumeration "urn:oasis:names:tc:SAML:2.0:protocol"}
      [:md:KeyDescriptor  {:use "signing"}
       [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
        [:ds:X509Data
         [:ds:X509Certificate certificate-str]]]]
      [:md:KeyDescriptor  {:use "encryption"}
       [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
        [:ds:X509Data
         [:ds:X509Certificate certificate-str]]]]
      [:md:SingleLogoutService {:Binding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                :Location "https://example.org/saml/SingleLogout"}]
      [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
      [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
      [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
      [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"]
      [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"]
      [:md:AssertionConsumerService {:Binding   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     :Location  acs-uri
                                     :index     "0"
                                     :isDefault "true"}]]])))

(defn create-request
  "Return XML elements that represent a SAML 2.0 auth request."
  [time-issued saml-format saml-service-name saml-id acs-url idp-uri]
  (str
    (h.page/xml-declaration "UTF-8")
    (hiccup/html
      [:samlp:AuthnRequest
       {:xmlns:samlp                 "urn:oasis:names:tc:SAML:2.0:protocol"
        :ID                          saml-id
        :Version                     "2.0"
        :IssueInstant                time-issued
        :ProtocolBinding             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        :ProviderName                saml-service-name
        :IsPassive                   false
        :Destination                 idp-uri
        :AssertionConsumerServiceURL acs-url}
       [:saml:Issuer
        {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"}
        saml-service-name]
       ;;[:samlp:NameIDPolicy {:AllowCreate false :Format saml-format}]
       ])))

(defn generate-mutables
  []
  {:saml-id-timeouts (ref {})
   :saml-last-id     (atom 0)
   :secret-key-spec  (shared/new-secret-key-spec)})

(defn create-request-factory
  "Creates new requests for a particular service, format, and acs-url."
  ([mutables idp-uri saml-format saml-service-name acs-url]
   (create-request-factory
     #(str "_" (next-saml-id! (:saml-last-id mutables)))
     (partial bump-saml-id-timeout! (:saml-id-timeouts mutables))
     (:xml-signer mutables)
     idp-uri saml-format saml-service-name acs-url))
  ([next-saml-id-fn! bump-saml-id-timeout-fn! xml-signer idp-uri saml-format saml-service-name acs-url]
   ;;; Bootstrap opensaml when we create a request factory.
   ;;; TODO: Figure out if this can be called more than once.
   (org.opensaml.DefaultBootstrap/bootstrap)
   (fn request-factory []
     (let [current-time  (ctime/now)
           new-saml-id   (next-saml-id-fn!)
           issue-instant (shared/make-issue-instant current-time)
           new-request   (create-request issue-instant
                                         saml-format
                                         saml-service-name
                                         new-saml-id
                                         acs-url
                                         idp-uri)]
       (bump-saml-id-timeout-fn! new-saml-id current-time)
       (if xml-signer
         (xml-signer new-request)
         new-request)))))

(defn get-idp-redirect
  "Return Ring response for HTTP 302 redirect."
  [idp-url saml-request relay-state]
  (let [url (str idp-url
                 "?"
                 (let [saml-request (shared/str->deflate->base64 saml-request)]
                   (shared/uri-query-str
                    {:SAMLRequest saml-request :RelayState relay-state})))]
    {:status  302 ; found
     :headers {"Location" url}
     :body    ""}))

(defn pull-attrs
  [loc attrs]
  (zipmap attrs (map (partial zf/attr loc) attrs)))

(defn response->map
  "Parses and performs final validation of the request. An exception will be thrown if validation fails."
  [saml-resp]
  (let [response-attr-names       [:ID :IssueInstant :InResponseTo]
        subject-conf-names        [:Recipient :NotOnOrAfter :InResponseTo]
        saml-cond-attr-names      [:NotBefore :NotOnOrAfter]
        saml-status               (zf/xml1-> saml-resp :samlp:Status :samlp:StatusCode)
        saml-assertion            (zf/xml1-> saml-resp :Assertion)
        saml-subject              (zf/xml1-> saml-assertion :Subject)
        saml-issuer               (zf/xml1-> saml-assertion :Issuer)
        saml-name-id              (zf/xml1-> saml-subject :NameID)
        saml-subject-conf-data    (zf/xml1-> saml-subject :SubjectConfirmation :SubjectConfirmationData)
        saml-conditions           (zf/xml1-> saml-assertion :Conditions)
        saml-audience-restriction (zf/xml1-> saml-conditions :AudienceRestriction :Audience)
        response-attrs            (pull-attrs saml-resp response-attr-names)
        status-str                (zf/attr saml-status :Value)
        issuer                    (zf/text saml-issuer)
        user-identifier           (zf/text saml-name-id)
        user-type                 (zf/attr saml-name-id :Format)
        conditions                (pull-attrs saml-conditions saml-cond-attr-names)
        subject-conf-attrs        (pull-attrs saml-subject-conf-data subject-conf-names)
        acs-audience              (zf/text saml-audience-restriction)]
    {:responding-to   (:InResponseTo response-attrs)
     :response-id     (:ID response-attrs)
     :issued-at       (:IssueInstant response-attrs)
     ;; TODO: Validate that "now" is within saml conditions.
     :success?        (and (shared/saml-successful? status-str)
                           (= (:InResponseTo response-attrs)
                              (:InResponseTo subject-conf-attrs)))
     :user-format     user-type
     :user-identifier user-identifier}))

(defn parse-saml-response
  "Does everything from parsing the verifying saml data to returning it in an easy to use map."
  [raw-response]
  (let [xml           (parse (shared/str->inputstream raw-response))
        parsed-zipper (zip/xml-zip xml)]
    (response->map parsed-zipper)))

(defn make-saml-signer
  [keystore-filename, ^String keystore-password, key-alias & {:keys [algorithm] :or {algorithm :sha1}}]
  (when keystore-filename
    (Init/init)
    (ElementProxy/setDefaultPrefix Constants/SignatureSpecNS "")
    (let [ks          (shared/load-key-store keystore-filename keystore-password)
          private-key (.getKey ks key-alias (.toCharArray keystore-password))
          cert        (shared/x509-certificate-from-keystore ks key-alias)
          sig-algo    (case (.getAlgorithm private-key)
                        "DSA" (case algorithm
                                :sha256 org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_DSA_SHA256
                                org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_DSA)
                        (case algorithm
                          :sha256 org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_RSA_SHA256
                          org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_RSA))]
      ;; https://svn.apache.org/repos/asf/santuario/xml-security-java/trunk/samples/org/apache/xml/security/samples/signature/CreateSignature.java
      ;; http://stackoverflow.com/questions/2052251/is-there-an-easier-way-to-sign-an-xml-document-in-java
      ;; Also useful: http://www.di-mgt.com.au/xmldsig2.html
      (fn sign-xml-doc [^String xml-string]
        (let [xmldoc        (saml-xml/str->xmldoc xml-string)
              transforms    (doto (Transforms. xmldoc)
                              (.addTransform Transforms/TRANSFORM_ENVELOPED_SIGNATURE)
                              (.addTransform Transforms/TRANSFORM_C14N_EXCL_OMIT_COMMENTS))
              sig           (org.apache.xml.security.signature.XMLSignature. xmldoc nil sig-algo
                                 Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
              canonicalizer (Canonicalizer/getInstance Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)]
          (.. xmldoc
              (getDocumentElement)
              (appendChild (.getElement sig)))
          (doto sig
            (.addDocument "" transforms Constants/ALGO_ID_DIGEST_SHA1)
            (.addKeyInfo cert)
            (.addKeyInfo (.getPublicKey cert))
            (.sign private-key))
          (String. (.canonicalizeSubtree canonicalizer xmldoc) "UTF-8"))))))

(defn make-saml-decrypter [keystore-filename, ^String keystore-password, ^String key-alias]
  (when keystore-filename
    (let [ks              (shared/load-key-store keystore-filename keystore-password)
          private-key     (.getKey ks key-alias (.toCharArray keystore-password))
          decryption-cred (doto (org.opensaml.xml.security.x509.BasicX509Credential.)
                            (.setPrivateKey private-key))
          decrypter       (org.opensaml.saml2.encryption.Decrypter.
                           nil
                           (org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver. decryption-cred)
                           (org.opensaml.xml.encryption.InlineEncryptedKeyResolver.))]
      decrypter)))

;; http://kevnls.blogspot.gr/2009/07/processing-saml-in-java-using-opensaml.html
;; http://stackoverflow.com/questions/9422545/decrypting-encrypted-assertion-using-saml-2-0-in-java-using-opensaml
(defn parse-saml-assertion
  "Returns the attributes and the 'audiences' for the given SAML assertion"
  [^Assertion assertion]
  (let [statements                (.getAttributeStatements assertion)
        subject                   (.getSubject assertion)
        subject-confirmation-data (.getSubjectConfirmationData ^SubjectConfirmation (first (.getSubjectConfirmations subject)))
        name-id                   (.getNameID subject)
        attrs                     (into {} (for [^AttributeStatement statement statements
                                                 ^Attribute attribute          (.getAttributes statement)]
                                             [(shared/saml2-attr->name (.getName attribute)) ; Or (.getFriendlyName a) ??
                                              (map #(-> ^org.opensaml.xml.XMLObject % .getDOM .getTextContent)
                                                   (.getAttributeValues attribute))]))
        audiences                 (for [^AudienceRestriction restriction (-> assertion .getConditions .getAudienceRestrictions)
                                        ^Audience audience               (.getAudiences restriction)]
                                    (.getAudienceURI audience))]
    {:attrs attrs, :audiences audiences
     :name-id
     {:value  (some-> name-id .getValue)
      :format (some-> name-id .getFormat)}
     :confirmation
     {:in-response-to  (.getInResponseTo subject-confirmation-data)
      :not-before      (to-timestamp (.getNotBefore subject-confirmation-data))
      :not-on-or-after (to-timestamp (.getNotOnOrAfter subject-confirmation-data))
      :recipient       (.getRecipient subject-confirmation-data)}}))

(defn validate-saml-response-signature
  "Checks (if exists) the signature of SAML Response given the IdP certificate"
  [^Response saml-resp, idp-cert]
  (if-let [signature (.getSignature saml-resp)]
    (let [idp-pubkey   (-> idp-cert shared/certificate-x509 shared/jcert->public-key)
          public-creds (doto (org.opensaml.xml.security.x509.BasicX509Credential.)
                         (.setPublicKey idp-pubkey))
          validator    (org.opensaml.xml.signature.SignatureValidator. public-creds)]
      (try
        (.validate validator signature)
        true
        (catch org.opensaml.xml.validation.ValidationException e
          (log/error e "Signature NOT valid")
          false)))
    true ;; if not signature is present
    ))

(defn parse-saml-resp-status
  "Parses and returns information about the status (i.e. successful or not), the version, addressing info etc. of the
  SAML response

  Check the javadoc of OpenSAML at:

  https://build.shibboleth.net/nexus/service/local/repositories/releases/archive/org/opensaml/opensaml/2.5.3/opensaml-2.5.3-javadoc.jar/!/index.html"
  [^Response saml-resp]
  (let [status (.. saml-resp getStatus getStatusCode getValue)]
    {:inResponseTo (.getInResponseTo saml-resp)
     :status       status
     :success?     (= status org.opensaml.saml2.core.StatusCode/SUCCESS_URI)
     :version      (.. saml-resp getVersion toString)
     :issueInstant (to-timestamp (.getIssueInstant saml-resp))
     :destination  (.getDestination saml-resp)}))

(defn xml-string->saml-resp
  "Parses a SAML response (XML string) from IdP and returns the corresponding (Open)SAML Response object"
  [xml-string]
  (let [xmldoc              (.getDocumentElement (saml-xml/str->xmldoc xml-string))
        unmarshallerFactory (org.opensaml.Configuration/getUnmarshallerFactory)
        unmarshaller        (.getUnmarshaller unmarshallerFactory xmldoc)
        saml-resp           (.unmarshall unmarshaller xmldoc)]
    saml-resp))

(defn saml-resp->assertions
  "Returns the assertions (encrypted or not) of a SAML Response object"
  [^Response saml-resp, ^Decrypter decrypter]
  (let [assertions (concat (.getAssertions saml-resp)
                           (when decrypter
                             (map #(.decrypt decrypter ^EncryptedAssertion %)
                                  (.getEncryptedAssertions saml-resp))))
        props      (map parse-saml-assertion assertions)]
    (assoc (parse-saml-resp-status saml-resp)
           :assertions props )))
