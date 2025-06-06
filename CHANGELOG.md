## v1.0.0 - 2025-05-03 - Long overdue 1.0

Noteworthy Changes:

* Complete removal of SPF record support, records should be transitioned to TXT
  values before updating to this version.

Changes:

* Address pending octoDNS 2.x deprecations, require minimum of 1.5.x

## v0.0.5 - 2024-06-20 - refactor API code

* Use a common code base for ConstellixClient and SonarClient
* Prepare the authZ code for v4 (Authorization: Bearer)
* Support for Provider.list_zones to enable dynamic zone config when operating
  as a source

## v0.0.4 - 2023-09-24 - ordering is important

* Fix for presistent changes in dynamic rule ordering
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
