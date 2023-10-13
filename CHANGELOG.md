## v0.1.0 - 20xx-yy-zz - implement full-fledged and default healthchecks

* Support obey, up, down for status
* Fix the PUT based update methods
* Use the healthcheck configuration as per [dynamic records documentation](https://github.com/octodns/octodns/blob/main/docs/dynamic_records.md)
* Use the old provider specific healtheck config with preference, if present
* Use real updates instead of delete/recreate for healthchecks and pools

## v0.0.4 - 2023-09-24 - ordering is important

* Fix for persistent changes in dynamic rule ordering
* All HTTP requests include a meaningful user agent

## v0.0.3 - 2022-11-28 - implicit fallback leads to changes

* fix fallback attribute in dynamic to no longer be implicit
* align provider with SUPPORTS_ROOT_NS feature requirements
* remove params to `super()` calls
* multiple dependency version updates
* miscellaneous script/tooling improvements

## v0.0.2 - 2022-02-02 - pycountry-convert install_requires

* install_requires includes pycountry-convert as it's a runtime requirement
* other misc script/tooling improvements

## v0.0.1 - 2022-01-04 - Moving

#### Nothworthy Changes

* Initial extraction of ConstellixProvider from octoDNS core

#### Stuff

Nothing
