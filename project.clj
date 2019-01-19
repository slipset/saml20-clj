(defproject k2n/saml20-clj "0.1.10-SNAPSHOT"
  :description "Basic SAML 2.0 library for SSO."
  :url "https://github.com/k2n/saml20-clj"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :source-paths ["src"]
  :deploy-repositories [["releases" :clojars]
                        ["snaphosts" :clojars]]
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [clj-time "0.15.1"]
                 [ring "1.7.1"]
                 [org.apache.santuario/xmlsec "2.1.2"]
                 [compojure "1.6.1"]
                 [org.opensaml/opensaml "2.6.4"]
                 [org.clojure/data.xml "0.0.8"]
                 [org.clojure/data.codec "0.1.1"]
                 [org.clojure/data.zip "0.1.2"]
                 [org.vlacs/helmsman "1.0.0"]]
  :pedantic :warn
  :profiles {:dev {:source-paths ["dev" "test"]
                   :dependencies [[org.clojure/tools.namespace "0.2.10"]
                                  [nrepl/nrepl "0.5.3"]
                                  [hiccup "1.0.5"]
                                  [http-kit "2.3.0"]]}})
