(ns saml20-clj.specs
  (:require [clojure.spec.alpha :as s])
  (:import java.net.URL))

(defn url? [s]
  (try
    (URL. s)
    true
    (catch Exception _
      false)))


(s/def ::acs-url url?)
(s/def ::idp-url url?)
