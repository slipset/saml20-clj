(ns saml20-clj.sp.metadata
  (:require [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [saml20-clj
             [coerce :as coerce]
             [encode-decode :as encode]
             [specs :as specs]])
  (:import javax.security.cert.X509Certificate))

(defn url? [s]
  (string? s))

(s/def ::app-name string?)
(s/def ::slo-url specs/url?)
(s/def ::sp-cert (partial instance? X509Certificate))
(s/def ::requests-signed boolean?)
(s/def ::want-assertions-signed boolean?)

(s/def ::metadata (s/keys :req-un [::specs/acs-url
                                   ::app-name
                                   ::sp-cert]
                          :opt-un [::requests-signed
                                   ::slo-url
                                   ::want-assertions-signed]))

(s/fdef metadata
  :args (s/cat :args ::metadata)
  :ret string?)
(defn metadata [{:keys [app-name acs-url slo-url sp-cert
                        requests-signed
                        want-assertions-signed]
                 :or {want-assertions-signed true
                      requests-signed true}}]
  (let [encoded-cert (some-> ^X509Certificate sp-cert
                             .getEncoded
                             encode/encode-base64
                             encode/bytes->str)]
    (coerce/->xml-string
     [:md:EntityDescriptor {:xmlns:md "urn:oasis:names:tc:SAML:2.0:metadata"
                            :ID       (str/replace acs-url #"[:/]" "_")
                            :entityID app-name}
      [:md:SPSSODescriptor {:AuthnRequestsSigned        (str requests-signed)
                            :WantAssertionsSigned       (str want-assertions-signed)
                            :protocolSupportEnumeration "urn:oasis:names:tc:SAML:2.0:protocol"}
       (when encoded-cert
         [:md:KeyDescriptor  {:use "signing"}
          [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
           [:ds:X509Data
            [:ds:X509Certificate encoded-cert]]]])
       (when encoded-cert
         [:md:KeyDescriptor  {:use "encryption"}
          [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
           [:ds:X509Data
            [:ds:X509Certificate encoded-cert]]]])
       (when slo-url
         [:md:SingleLogoutService {:Binding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                   :Location slo-url}])
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"]
       [:md:AssertionConsumerService {:Binding   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                      :Location  acs-url
                                      :index     "0"
                                      :isDefault "true"}]]])))
