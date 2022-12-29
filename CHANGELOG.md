## v2.8.0 (2022-12-29)

### Feat

- **api**: add tests for create_authz_scopes

### Fix

- fix testing create_client_authz_scopes parameters
- fix linting
- add testcase for invalid client id
- create authz clients test case
- create authz clients test case

## v2.7.0 (2022-12-24)

### Refactor

- code formatting after tox checks
- remove print statements

## v2.6.1 (2022-12-13)

### Feat

- option for enabling users
- helping functions for disabling users

### Fix

- use version from the package
- default scope to openid

## v2.6.0 (2022-10-03)

### Feat

- attack detection API implementation

## v2.5.0 (2022-08-19)

## v2.4.0 (2022-08-19)

### Feat

- add client scope-mappings client roles operations
- added missing functionality to include attributes when returning realm roles according to specifications

## v2.3.0 (2022-08-13)

### Feat

- Add token_type/scope to token exchange api

## v2.2.0 (2022-08-12)

### Feat

- add client scope-mappings realm roles operations

## v2.1.1 (2022-07-19)

### Fix

- removed whitespace from urls

### Refactor

- applied linting

## v2.1.0 (2022-07-18)

### Feat

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

### BREAKING CHANGE

- Renamed parameter client_name to client_id in get_client_id method

### Fix

- check client existence based on clientId

## v1.9.1 (2022-07-13)

### Fix

- turn get_name into a method, use setters in connection manager

### Refactor

- no need to try if the type check is performed

## v1.9.0 (2022-07-13)

### Refactor

- merge master branch into local

## v1.8.1 (2022-07-13)

### Feat

- added flake8-docstrings and upgraded dependencies

### Fix

- Support the auth_url method called with scope & state params now
- raise correct exceptions

### Refactor

- slight restructure of the base fixtures

## v1.8.0 (2022-06-22)

### Feat

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

## v1.4.0 (2022-06-02)

### Feat

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

## v1.0.0 (2022-05-25)

### BREAKING CHANGE

- Renames `KeycloakOpenID.well_know` to `KeycloakOpenID.well_known`

### Fix

- correct spelling of public API method

## v0.29.1 (2022-05-24)

### Fix

- allow client_credentials token if username and password not specified

## v0.29.0 (2022-05-23)

### Fix

- added fixes based on feedback

## v0.28.3 (2022-05-23)

### Feat

- added UMA-permission request functionality

### Fix

- import classes in the base module

## v0.28.2 (2022-05-19)

### Fix

- escape when get role fails

## v0.28.1 (2022-05-19)

### Fix

- Add missing keycloak.authorization package

## v0.28.0 (2022-05-19)

## v (2022-05-19)

### Feat

- added authenticator providers getters
- fixed admin client to pass the tests
- initial setup of CICD and linting

### Fix

- full tox fix ready
- raise correct errors

### Refactor

- isort conf.py
- Merge branch 'master' into feature/cicd

## v0.27.1 (2022-05-18)

### Fix

- **release**: version bumps for hotfix release

## v0.27.0 (2022-02-16)

### Fix

- handle refresh_token error "Session not active"

## v0.26.1 (2021-08-30)

### Feat

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
