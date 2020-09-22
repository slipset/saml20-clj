# saml20-clj

[![Downloads](https://versions.deps.co/metabase/saml20-clj/downloads.svg)](https://versions.deps.co/metabase/saml20-clj)
[![Dependencies Status](https://versions.deps.co/metabase/saml20-clj/status.svg)](https://versions.deps.co/metabase/saml20-clj)
[![Circle CI](https://circleci.com/gh/metabase/saml20-clj.svg?style=svg)](https://circleci.com/gh/metabase/saml20-clj)
[![codecov](https://codecov.io/gh/metabase/saml20-clj/branch/master/graph/badge.svg)](https://codecov.io/gh/metabase/saml20-clj)
[![License](https://img.shields.io/badge/license-Eclipse%20Public%20License-blue.svg)](https://raw.githubusercontent.com/metabase/saml20-clj/master/LICENSE)
[![cljdoc badge](https://cljdoc.org/badge/metabase/saml20-clj)](https://cljdoc.org/d/metabase/saml20-clj/CURRENT)

[![Clojars Project](https://clojars.org/metabase/saml20-clj/latest-version.svg)](http://clojars.org/metabase/saml20-clj)


This is a SAML 2.0 clojure library for SSO.
This library allows a clojure application to act as a service provider (SP).
Tested with Microsoft Active Directory Federation Server (ADFS) as the identity provider (IdP), as well as Okta and OneLogin.

## Usage

*  See [quephird/saml-test](https://github.com/quephird/saml-test) for the usage.
*  This repository is forked from [vlacs/saml20-clj](https://github.com/vlacs/saml20-clj), and adds:
   *  Tons of bug fixes, such as `saml20-clj.shared/base64->inflate->str` not actually calling `byte-inflate` at all
   *  Fixed millions of reflection warnings
   *  Removed duplicate functions
   *  Support for XML signing with SHA-256 instead of SHA-1, which is required by ADFS by default (via [k2n/saml20-clj](https://github.com/k2n/saml20-clj))
   *  Support for Clojure 1.10+
   *  Support for base-64 encodings that contain newlines

## License

* Copyright © 2013 VLACS <jdoane@vlacs.org>
* Copyright © 2017 Kenji Nakamura <kenji@signifier.jp>
* Copyright © 2019-2020 [Metabase, Inc.](https://metabase.com)

Distributed under the Eclipse Public License, the same as Clojure.
