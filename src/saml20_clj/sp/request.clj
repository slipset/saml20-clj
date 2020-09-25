(ns saml20-clj.sp.request
  (:require [clojure.string :as str]
            [java-time :as t]
            [ring.util.codec :as codec]
            [saml20-clj
             [coerce :as coerce]
             [crypto :as crypto]
             [encode-decode :as encode-decode]
             [specs :as specs]
             [state :as state]])
  (:import org.opensaml.security.credential.Credential
           org.w3c.dom.Element))

(defn- format-instant
  "Converts a date-time to a SAML 2.0 time string."
  [instant]
  (t/format (t/format "YYYY-MM-dd'T'HH:mm:ss'Z'" (t/offset-date-time instant (t/zone-offset 0)))))

(s/def ::request-id string?)
(s/def ::sp-name string?)
(s/def ::issuer specs/url?)
(s/def ::state-manager (partial satisfies? state/StateManager))
(s/def ::credential (partial instance? Credential))
(s/def ::instant inst?)

(s/def ::request (s/keys :req-un [::sp-name
                                  ::specs/acs-url
                                  ::specs/idp-url
                                  ::issuer]
                         :opt-un [::state-manager
                                  ::credential
                                  ::instant]))

(s/fdef request
  :args (s/cat :request ::request)
  :ret (partial instance? Element))
(defn request
  "Return XML elements that represent a SAML 2.0 auth request."
  ^Element [{:keys [ ;; e.g. something like a UUID
                    request-id
                    ;; e.g. "Metabase"
                    sp-name
                    ;; e.g. ttp://sp.example.com/demo1/index.php?acs
                    acs-url
                    ;; e.g. http://sp.example.com/demo1/index.php?acs
                    idp-url
                    ;; e.g. http://idp.example.com/SSOService.php
                    issuer
                    ;; If present, record the request
                    state-manager
                    ;; If present, we can sign the request
                    credential
                    instant]
             :or   {request-id (str (java.util.UUID/randomUUID))
                    instant (t/instant)}}]
  (assert acs-url)
  (assert idp-url)
  (assert sp-name)
  (let [request (coerce/->Element (coerce/->xml-string
                                   [:samlp:AuthnRequest
                                    {:xmlns:samlp                 "urn:oasis:names:tc:SAML:2.0:protocol"
                                     :ID                          request-id
                                     :Version                     "2.0"
                                     :IssueInstant                (format-instant instant)
                                     :ProtocolBinding             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     :ProviderName                sp-name
                                     :IsPassive                   false
                                     :Destination                 idp-url
                                     :AssertionConsumerServiceURL acs-url}
                                    [:saml:Issuer
                                     {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"}
                                     issuer]
                                    ;;[:samlp:NameIDPolicy {:AllowCreate false :Format saml-format}]
                                    ]))]
    (when state-manager
      (state/record-request! state-manager (.getAttribute request "ID")))
    (if-not credential
      request
      (or (crypto/sign request credential)
          (throw (ex-info "Failed to sign request" {:request request}))))))

(defn uri-query-str
  ^String [clean-hash]
  (codec/form-encode clean-hash))

(s/def ::saml-request (partial satisfies? coerce/SerializeXMLString))
(s/def ::relay-state string?)

(s/def ::status int?)
(s/def ::headers map?)
(s/def ::body string?)

(s/def ::ring-response (s/keys :req-un [::status ::headers ::body]))

(s/fdef id-redirect-response
  :args (s/cat :request ::saml-request
               :idp-url ::specs/idp-url
               :relay-state ::relay-state)
  :ret ::ring-response)

(defn idp-redirect-response
  "Return Ring response for HTTP 302 redirect."
  [saml-request idp-url relay-state]
  {:pre [(some? saml-request) (string? idp-url) (string? relay-state)]}
  (let [saml-request-str (if (string? saml-request)
                           saml-request
                           (coerce/->xml-string saml-request))
        url              (str idp-url
                              (if (str/includes? idp-url "?")
                                "&"
                                "?")
                              (let [saml-request-str (encode-decode/str->deflate->base64 saml-request-str)]
                                (uri-query-str
                                 {:SAMLRequest saml-request-str, :RelayState relay-state})))]
    {:status  302 ; found
     :headers {"Location" url}
     :body    ""}))
