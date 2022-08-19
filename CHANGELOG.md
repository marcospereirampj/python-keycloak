# Changelog

## v2.5.0 (2022-08-19)

### Feat

- added missing functionality to include attributes when returning realm roles according to specifications

## v2.4.0 (2022-08-19)

### Feat

- add client scope-mappings client roles operations

## v2.3.0 (2022-08-13)

### Feat

- Add token_type/scope to token exchange api

## v2.2.0 (2022-08-12)

### Feat

- add client scope-mappings realm roles operations

## v2.1.1 (2022-07-19)

### Refactor

- applied linting

### Fix

- removed whitespace from urls

## v2.1.0 (2022-07-18)

### Feat

- add functions covering some missing REST API calls
- add unit tests
- add docstrings
- add functions covering some missing REST API calls

### Fix

- linting
- now get_required_action_by_alias now returns None if action does not exist
- moved imports at the top of the file
- remove duplicate function
- applied tox -e docs
- applied flake linting checks
- applied tox linting check

## v2.0.0 (2022-07-17)

### Fix

- check client existence based on clientId
- check client existence based on clientId

### BREAKING CHANGE

- Renamed parameter client_name to client_id in get_client_id method

## v1.9.1 (2022-07-13)

### Fix

- turn get_name into a method, use setters in connection manager

### Refactor

- no need to try if the type check is performed

## v1.9.0 (2022-07-13)

### Refactor

- merge master branch into local

## v1.8.1 (2022-07-13)

### Fix

- Support the auth_url method called with scope & state params now
- Support the auth_url method called with scope & state params now
- raise correct exceptions

### Feat

- added flake8-docstrings and upgraded dependencies
- use poetry for package management

### Refactor

- slight restructure of the base fixtures

## v1.8.0 (2022-06-22)

### Feat

- Ability to set custom timeout for KeycloakOpenId and KeycloakAdmin
- Ability to set custom timeout for KCOpenId and KCAdmin

## v1.7.0 (2022-06-16)

### Feat

- Allow fetching existing policies before calling create_client_authz_client_policy()

## v1.6.0 (2022-06-13)

### Feat

- support token exchange config via admin API

## v1.5.0 (2022-06-03)

### Feat

- Add update_idp
- Add update_idp

## v1.4.0 (2022-06-02)

### Feat

- Add update_mapper_in_idp
- Add update_mapper_in_idp

## v1.3.0 (2022-05-31)

## v1.2.0 (2022-05-31)

### Feat

- Add get_idp_mappers, fix #329
- Support Token Exchange. Fixes #305

## v1.1.1 (2022-05-27)

### Fix

- fixed bugs in events methods
- fixed components bugs
- use param for update client mapper

## v1.1.0 (2022-05-26)

### Feat

- added new methods for client scopes

## v1.0.1 (2022-05-25)

### Fix

- allow query parameters for users count
- allow query parameters for users count

## v1.0.0 (2022-05-25)

### Fix

- correct spelling of public API method

### BREAKING CHANGE

- Renames `KeycloakOpenID.well_know` to `KeycloakOpenID.well_known`

## v0.29.1 (2022-05-24)

### Fix

- allow client_credentials token if username and password not spec…
- allow client_credentials token if username and password not specified

## v0.29.0 (2022-05-23)

### Fix

- added fixes based on feedback

## v0.28.3 (2022-05-23)

### Fix

- import classes in the base module
- import classes in the base module

### Feat

- added UMA-permission request functionality

## v0.28.2 (2022-05-19)

### Fix

- escape when get role fails

## v0.28.1 (2022-05-19)

### Fix

- Add missing keycloak.authorization package
- Add missing keycloak.authorization package

## v0.28.0 (2022-05-19)

## v (2022-05-19)

### Feat

- added authenticator providers getters
- fixed admin client to pass the tests
- initial setup of CICD and linting

### Refactor

- isort conf.py
- Merge branch 'master' into feature/cicd

### Fix

- full tox fix ready
- raise correct errors

## v0.27.1 (2022-05-18)

### Fix

- **release**: version bumps for hotfix release

## v0.27.0 (2022-02-16)

### Fix

- handle refresh_token error "Session not active"

## v0.26.1 (2021-08-30)

### Feat

- add KeycloakAdmin.set_events
- add KeycloakAdmin.set_events

## v0.25.0 (2021-05-05)

## v0.24.0 (2020-12-18)

## 0.23.0 (2020-11-19)

## v0.22.0 (2020-08-16)

## v0.21.0 (2020-06-30)

### Feat

- add components

## v0.20.0 (2020-04-11)

## v0.19.0 (2020-02-18)

## v0.18.0 (2019-12-10)

## v0.17.6 (2019-10-10)

## v0.5.0 (2017-08-21)

### Feat

- Basic functions for Keycloak API (well_know, token, userinfo, logout, certs,
  entitlement, instropect)

## v0.6.0 (2017-08-23)

### Feat

- Added load authorization settings

## v0.7.0 (2017-08-23)

### Feat

- Added polices

## v0.8.0 (2017-08-23)

### Feat

- Added permissions

## v0.9.0 (2017-09-05)

### Feat

- Added functions for Admin Keycloak API

## v0.10.0 (2017-10-23)

### Feat

- Updated libraries versions
- Updated Docs

## v0.11.0 (2017-12-12)

### Feat

- Changed Instropect RPT

## v0.12.0 (2018-01-25)

### Feat

- Add groups functions
- Add Admin Tasks for user and client role management
- Function to trigger user sync from provider

## v0.12.1 (2018-08-04)

### Feat

- Add get_idps
- Rework group functions

## master

### Feat

- Renamed `KeycloakOpenID.well_know` to `KeycloakOpenID.well_known`
- Add `KeycloakOpenID.token_exchange` to support Token Exchange
