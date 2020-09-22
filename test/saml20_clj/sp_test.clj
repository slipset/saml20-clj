(ns saml20-clj.sp-test
  (:require [clj-time.core :as ctime]
            [clojure.test :refer :all]
            [saml20-clj.sp :as sp]))

(deftest next-saml-id-test
  (testing "test saml next-id: Changing saml last id state."
    (is (= 1
           (sp/next-saml-id! (atom 0))))))

(deftest timeout-bump-test
  (testing "test saml timeout-bump: Attempt to bump a stateful saml timeout on a fake request."
    (let [time-now (ctime/now)]
      (is (= time-now
             (let [mutable (ref {})
                   saml-id 12345]
               (sp/bump-saml-id-timeout! mutable saml-id time-now)
               (get @mutable saml-id)))))))

(deftest prune-timed-out-ids-test
  (testing "test prune timed out ids: Attempt to remove a stale record from a mutable hash."
    (is (= {:count 1, :get-1? false, :get-2? true}
           (let [mutable (ref {1 (ctime/date-time 2013 10 10)
                               2 (ctime/now)})
                 timeout (ctime/minutes 10)]
             (sp/prune-timed-out-ids! mutable timeout)
             {:count  (count @mutable)
              :get-1? (some? (get @mutable 1))
              :get-2? (some? (get @mutable 2))})))))

(deftest get-idp-redirect-test
  (is (= {:status 302
          :headers {"Location" (str "https://idp.example.com"
                                    "?SAMLRequest=C3b09VEIcg0MdQ0OUXD3dw1W8HANcgUA"
                                    "&RelayState=http%3A%2F%2Fexample.com%2Fredirect%2Fback%2Fto%2Fhere")}
          :body ""}
         (sp/get-idp-redirect "https://idp.example.com"
                              "SAML REQUEST GOES HERE"
                              "http://example.com/redirect/back/to/here"))))
