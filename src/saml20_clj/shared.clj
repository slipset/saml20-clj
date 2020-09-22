(ns saml20-clj.shared
  (:require [clj-time
             [core :as ctime]
             [format :as ctimeformat]]
            [clojure
             [string :as str]
             [xml :as xml]
             [zip :as zip]]
            [clojure.java.io :as io]
            [ring.util.codec :as codec])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]
           java.nio.charset.Charset
           [java.security KeyStore PublicKey]
           [java.security.cert Certificate CertificateFactory X509Certificate]
           java.util.Random
           [java.util.zip Deflater DeflaterOutputStream Inflater InflaterInputStream]
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec
           [org.apache.commons.codec.binary Base64 Hex]
           org.apache.commons.io.IOUtils))

(def instant-format (ctimeformat/formatters :date-time-no-ms))
(def ^Charset utf-charset (Charset/forName "UTF-8"))

(def status-code-success "urn:oasis:names:tc:SAML:2.0:status:Success")

(defn saml-successful?
  [id-str]
  (= id-str status-code-success))

(defn jcert->public-key
  "Extracts a public key object from a java cert object."
  ^PublicKey [^Certificate certificate]
  (.getPublicKey certificate))

(defn parse-xml-str
  [^String xml-str]
  (zip/xml-zip (xml/parse (ByteArrayInputStream. (.getBytes xml-str)))))


(defn clean-x509-filter
  "Turns a base64 string into a byte array to be decoded, which includes sanitization
   and removal of ASCII armor"
  ^bytes [^String x509-string]
  (-> x509-string
      (str/replace #"-----BEGIN CERTIFICATE-----" "")
      (str/replace #"-----END CERTIFICATE-----" "")
      (str/replace #"[\n ]" "")
      ((partial map byte))
      byte-array
      bytes))

(defn certificate-x509
  "Takes in a raw X.509 certificate string, parses it, and creates a Java certificate."
  ^Certificate [^String x509-string]
  (let [x509-byte-array (clean-x509-filter x509-string)
        cert-factory    (CertificateFactory/getInstance "X.509")]
    (with-open [is (ByteArrayInputStream. (Base64/decodeBase64 x509-byte-array))]
      (.generateCertificate cert-factory is))))


(defn str->inputstream
  "Unravels a string into an input stream so we can work with Java constructs."
  ^ByteArrayInputStream [^String unravel]
  (ByteArrayInputStream. (.getBytes unravel utf-charset)))

(defn make-issue-instant
  "Converts a date-time to a SAML 2.0 time string."
  [ii-date]
  (ctimeformat/unparse instant-format ii-date))

(defn str->bytes
  ^bytes [^String some-string]
  (.getBytes some-string utf-charset))

(defn bytes->str
  ^String [^bytes some-bytes]
  (String. some-bytes utf-charset))

(defn byte-deflate
  ^bytes [^bytes str-bytes]
  (with-open [byte-os     (ByteArrayOutputStream.)
              deflater-os (DeflaterOutputStream. byte-os (Deflater. -1 true) 1024)]
    (.write deflater-os str-bytes)
    (.finish deflater-os)
    (.toByteArray byte-os)))

(defn byte-inflate
  ^bytes [^bytes comp-bytes]
  (with-open [is (InflaterInputStream. (ByteArrayInputStream. comp-bytes) (Inflater. true) 1024)]
    (IOUtils/toByteArray is)))

(defn str->base64
  ^String [^String string]
  (-> string str->bytes Base64/encodeBase64 bytes->str))

(defn str->deflate->base64
  [^String string]
  (-> string str->bytes byte-deflate Base64/encodeBase64 bytes->str))

(defn base64->str
  ^String [^String string]
  (-> string str->bytes Base64/decodeBase64 bytes->str))

(defn base64->inflate->str
  [^String string]
  (-> string str->bytes Base64/decodeBase64 byte-inflate bytes->str))

(defn random-bytes
  (^bytes [size]
   (let [ba (byte-array size)
         r (Random.)]
     (.nextBytes r ba)
     ba))
  (^bytes []
   (random-bytes 20)))

(defn bytes->hex
  ^String [^bytes bytes-str]
  (Hex/encodeHexString bytes-str))

(defn new-secret-key-spec ^SecretKeySpec []
  (SecretKeySpec. (random-bytes) "HmacSHA1"))

(defn hmac-str
  ^String [^SecretKeySpec key-spec ^String string]
  (let [mac (doto (Mac/getInstance "HmacSHA1")
              (.init key-spec))
        hs (.doFinal mac (.getBytes string "UTF-8"))]
    (bytes->hex hs)))

(defn uri-query-str
  ^String [clean-hash]
  (codec/form-encode clean-hash))

(defn form-encode-b64
  [req]
  (into {}
        (map
         (fn [[k v]] [k (str->base64 v)])
         req)))

(defn saml-form-encode [form]
  (-> form
      form-encode-b64
      codec/form-encode))

(defn time-since
  [time-span]
  (ctime/minus (ctime/now) time-span))

(defn make-timeout-filter-fn
  "Creates a function for clojure.core/filter to keep all dates after
  a given date."
  [timespan]
  (fn [i]
    (ctime/after? (second i) (time-since timespan))))

(defn load-key-store
  ^KeyStore [keystore-filename, ^String keystore-password]
  (when (some-> keystore-filename io/as-file .exists)
    (with-open [is (io/input-stream keystore-filename)]
      (doto (KeyStore/getInstance "JKS")
        (.load is (.toCharArray keystore-password))))))

(defn x509-certificate-from-keystore
  ^X509Certificate [^KeyStore keystore, ^String cert-alias]
  (when-let [cert (.getCertificate keystore cert-alias)]
    (assert (instance? X509Certificate cert))
    cert))

(defn get-certificate-b64
  ^String [keystore-filename, ^String keystore-password, ^String cert-alias]
  (when-let [ks (load-key-store keystore-filename keystore-password)]
    (-> ks (.getCertificate cert-alias) .getEncoded Base64/encodeBase64 (String. "UTF-8"))))

;; https://www.purdue.edu/apps/account/docs/Shibboleth/Shibboleth_information.jsp
;;  Or
;; https://wiki.library.ucsf.edu/display/IAM/EDS+Attributes
(def saml2-attr->name
  (let [names {"urn:oid:0.9.2342.19200300.100.1.1" "uid"
               "urn:oid:0.9.2342.19200300.100.1.3" "mail"
               "urn:oid:2.16.840.1.113730.3.1.241" "displayName"
               "urn:oid:2.5.4.3"                   "cn"
               "urn:oid:2.5.4.4"                   "sn"
               "urn:oid:2.5.4.12"                  "title"
               "urn:oid:2.5.4.20"                  "phone"
               "urn:oid:2.5.4.42"                  "givenName"
               "urn:oid:2.5.6.8"                   "organizationalRole"
               "urn:oid:2.16.840.1.113730.3.1.3"   "employeeNumber"
               "urn:oid:2.16.840.1.113730.3.1.4"   "employeeType"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"  "eduPersonAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.2"  "eduPersonNickname"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"  "eduPersonPrincipalName"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"  "eduPersonScopedAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.10" "eduPersonTargetedID"
               "urn:oid:1.3.6.1.4.1.5923.1.6.1.1"  "eduCourseOffering"}]
    (fn [attr-oid]
      (get names attr-oid attr-oid) )))
