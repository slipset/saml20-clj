(defproject metabase/saml20-clj "2.0.0-SNAPSHOT"
  :description "Improved SAML 2.0 library for SSO."
  :url "https://github.com/metabase/saml20-clj"
  :min-lein-version "2.5.0"

  :license {:name "Eclipse Public License"
            :url  "https://raw.githubusercontent.com/metabase/saml20-clj/master/LICENSE"}

  :aliases
  {"test"                      ["with-profile" "+test" "test"]
   "bikeshed"                  ["with-profile" "+bikeshed" "bikeshed" "--max-line-length" "150"]
   "check-namespace-decls"     ["with-profile" "+check-namespace-decls" "check-namespace-decls"]
   "eastwood"                  ["with-profile" "+eastwood" "eastwood"]
   "check-reflection-warnings" ["with-profile" "+reflection-warnings" "check"]
   "cloverage"                 ["with-profile" "+cloverage" "cloverage"]
   ;; `lein lint` will run all linters
   "lint"                      ["do" ["eastwood"] ["bikeshed"] ["check-namespace-decls"] ["cloverage"]]}

  :dependencies
  [[org.clojure/data.xml "0.0.8"]
   [org.clojure/data.zip "1.0.0"]
   [org.clojure/tools.logging "1.1.0"]
   [clj-time "0.15.2"]
   [commons-io/commons-io "2.8.0"]
   [hiccup "1.0.5"]
   [org.apache.santuario/xmlsec "2.2.0"]
   [org.opensaml/opensaml "2.6.4"]
   [ring/ring-codec "1.1.2"]]           ; for the url-encode codec

  :profiles
  {:dev
   {:dependencies
    [[org.clojure/clojure "1.10.1"]
     [pjstadig/humane-test-output "0.10.0"]]

    :injections
    [(require 'pjstadig.humane-test-output)
     (pjstadig.humane-test-output/activate!)]

    :jvm-opts
    ["-Xverify:none"]}

   :expectations
   {:plugins [[lein-expectations "0.0.8" :exclusions [expectations]]]}

   :eastwood
   {:plugins
    [[jonase/eastwood "0.3.5" :exclusions [org.clojure/clojure]]]

    :add-linters
    [:unused-private-vars
     :unused-namespaces
     :unused-fn-args
     :unused-locals]

    :exclude-linters
    [:deprecations]}

   :bikeshed
   {:plugins
    [[lein-bikeshed "0.5.2"]]}

   :check-namespace-decls
   {:plugins               [[lein-check-namespace-decls "1.0.2"]]
    :source-paths          ["test"]
    :check-namespace-decls {:prefix-rewriting true}}

   :cloverage
   ;; Using Cam's fork of Cloverage until 1.2.1 of the main repo is out. Once that's released we can switch back.
   {:dependencies [[camsaul/cloverage "1.2.1.1"]]
    :plugins      [[camsaul/lein-cloverage  "1.2.1.1"]]
    :cloverage    {:fail-threshold 20}}}

  :deploy-repositories
  [["clojars"
    {:url           "https://clojars.org/repo"
     :username      :env/clojars_username
     :password      :env/clojars_password
     :sign-releases false}]])
