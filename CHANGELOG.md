## v5.5.1 (2025-05-25)

### Fix

- fix/latest version (#654)

## v5.5.0 (2025-04-09)

### Feat

- implement client for revoking consents/offline access, with async and improved testing (#644)

## v5.4.0 (2025-04-08)

### Feat

- adds support for keycloak organizations (#642)

## v5.3.1 (2025-02-03)

### Fix

- add py.typed marker file (pep-561) (#637)

## v5.3.0 (2025-02-02)

### Feat

- more authentication flows and executions methods

## v5.2.0 (2025-01-30)

### Feat

- Add functions to get/update realm users profile (#634)

## v5.1.2 (2025-01-26)

### Fix

- small bugs, use ruff as linter, added annotations

## v5.1.1 (2024-12-15)

### Fix

- retry upon 401

## v5.1.0 (2024-12-14)

### Feat

- get_client_all_sessions now supports pagination
- uma extra payload
- user profile metadata parameter for get_user method
- uma extra payload

### Fix

- check uma permissions with resource ID as well
- get group by path should not raise on 404

## v5.0.0 (2024-12-10)

## v4.7.3 (2024-11-29)

### Fix

- change to mounts (#622)

## v4.7.2 (2024-11-17)

### Fix

- Feature parity for `a_decode_token` and `decode_token` (#616)

## v4.7.1 (2024-11-13)

### Fix

- make sure to not call sync IO functions inside async functions (#615)

## v4.7.0 (2024-11-03)

### Feat

- add client scope client-specific role mappings (#605)

## v4.6.3 (2024-10-26)

### Fix

- Add optional Nonce parameter to the authorization URL requests (#606)

## v4.6.2 (2024-10-05)

### Fix

- add scopes to device auth (#599)

## v4.6.1 (2024-10-05)

### Fix

- changed sync get user id to async get user in create user async function (#600)

## v4.6.0 (2024-10-04)

### Feat

- Add the max_retries parameter (#598)

## v4.5.1 (2024-10-02)

### Fix

- Set client_credentials as grant_type also when x509 certificate is given (#597)

## v4.5.0 (2024-09-28)

### Feat

- add ability to remove composite client roles (#596)

## v4.4.0 (2024-09-14)

### Feat

- add matchingUri support for listing resources with wildcards (#592)

## v4.3.0 (2024-08-01)

### Feat

- allow the use of client certificates in all requests (#584)

## v4.2.3 (2024-07-24)

### Fix

- use a_public_key() in a_decode_token() instead of public_key() (#582)

## v4.2.2 (2024-07-16)

### Fix

- correctly pass query params in a_send_update_account and a_send_verify_email (#581)

## v4.2.1 (2024-07-11)

### Fix

- passing timeout values to ConnectionManager (#578)

## v4.2.0 (2024-06-22)

### Feat

- functions for updating resource permissions and getting associated policies for a permission (#574)

## v4.1.0 (2024-06-06)

### Feat

- Async feature (#566)

## v4.0.1 (2024-06-04)

### Fix

- Leeway config (#568)

## v4.0.0 (2024-04-27)

### BREAKING CHANGE

- changes signatures significantly
- Many attributes removed from the admin class

### Feat

- Merge pull request #556 from marcospereirampj/release/4.0.0
- re-enable full group hierarchy fetching

### Fix

- removed dead code, stabilized tests
- removed deprecated functionality

### Refactor

- refactored decode_token

## v3.12.0 (2024-04-10)

### Feat

- allows retrieval of realm and client level roles for a user (#512)

## v3.11.1 (2024-04-08)

### Fix

- lowercase default role name (#547)

## v3.11.0 (2024-04-08)

### Feat

- add admin group count (#540)

## v3.10.2 (2024-04-08)

### Fix

- fix keycloak_admin.create_user documentation/ typehint (#545)

## v3.10.1 (2024-04-07)

### Fix

- improve KeycloakAdmin.get_client_id() performances (#511)

## v3.10.0 (2024-04-07)

### Feat

- Allow query parameters for group children (#534)

## v3.9.3 (2024-04-07)

### Fix

- incorporate custom headers into default header setup (#533)

## v3.9.2 (2024-04-07)

### Fix

- get_groups pagination call was not used #537 (#541)

## v3.9.1 (2024-02-26)

### Fix

- use jwcrypto and remove python-jose
- replace python-jose with jwcrypto

## v3.9.0 (2024-02-16)

### Feat

- new docs.
- new docs.
- new docs.
- new docs.
- new docs.
- new docs.
- new docs.

### Fix

- updated readme.

## v3.8.4 (2024-02-15)

### Fix

- use grant type password with client secret

## v3.8.3 (2024-02-14)

### Fix

- name of client_id parameter

## v3.8.2 (2024-02-14)

### Fix

- update readme.

## v3.8.1 (2024-02-13)

### Fix

- linter check
- updated dependencies

## v3.8.0 (2024-02-13)

### Feat

- Adding additional methods to support roles-by-id api calls Most of the methods rely on the role name within python keycloak, which for the vast majority is fine, however there are some role names which cannot be used by the API endpoint as they contain characters that cannot be encoded properly. Therefore this change is to allow the use of the role's id to get, update and delete roles by their id instead.'

### Fix

- Removing the admin realm variable which I created and is no longer needed

## v3.7.1 (2024-02-13)

### Fix

- action bump
- linter check.
- depracated endpoint and fix groups services.
- deprecate entitlement

## v3.7.0 (2023-11-13)

### Feat

- realm changing helpers

### Fix

- no prints

## v3.6.1 (2023-11-13)

### Fix

- Ci/fix tests (#506)

## v3.6.0 (2023-11-13)

### Feat

- add KeycloakAdmin.get_idp() (#478)

## v3.5.0 (2023-11-13)

### Feat

- Update dynamic client using registration access token (#491)

## v3.4.0 (2023-11-13)

### Feat

- add an optional search criteria to the get_realm_roles function (#504)

## v3.3.0 (2023-06-27)

### Feat

- added KeycloakAdmin.update_client_authz_resource() (#462)

## v3.2.0 (2023-06-23)

### Feat

- Implement missing admin method create_client_authz_scope_based_permission() and create_client_authz_policy() (#460)

## v3.1.1 (2023-06-23)

### Fix

- remove duplicate slash in URL_ADMIN_IDP (#459)

## v3.1.0 (2023-06-23)

### Feat

- Add query to get users group method and permit pagination (#444)

## v3.0.0 (2023-05-28)

### BREAKING CHANGE

- Changes the exchange token API

### Refactor

- Exchange token method

## v2.16.6 (2023-05-28)

### Fix

- relax the version constraints

## v2.16.5 (2023-05-28)

### Fix

- do not swap realm for user_realm when logging in with a client service account (#447)

## v2.16.4 (2023-05-28)

### Perf

- improve performance of get_user_id (#449)

## v2.16.3 (2023-05-15)

### Fix

- Fixes `Authorization.load_config` breaking if a scope based permission is linked with anything other than a role based policy. Fixes #445 (#446)

## v2.16.2 (2023-05-09)

### Fix

- issue with app engine reported in #440 (#442)

## v2.16.1 (2023-05-01)

### Fix

- Initializing KeycloakAdmin without server_url (#439)

## v2.16.0 (2023-04-28)

### Feat

- Add get and delete methods for client authz resources (#435)

## v2.15.4 (2023-04-28)

### Fix

- **pyproject.toml**: loose requests pgk and remove urllib3 as dependency (#434)

## v2.15.3 (2023-04-06)

### Fix

- Check if _s exists in ConnectionManager before deleting it (#429)

## v2.15.2 (2023-04-05)

### Fix

- deprecation warnings in keycloak_admin.py (#425)

## v2.15.1 (2023-04-05)

### Fix

- improved type-hints (#427)

## v2.15.0 (2023-04-05)

### Feat

- Add UMA policy management and permission tickets (#426)

## v2.14.0 (2023-03-17)

### Feat

- add initial access token support and policy delete method

## v2.13.2 (2023-03-06)

### Fix

- Refactor auto refresh (#415)

## v2.13.1 (2023-03-05)

### Fix

- Check if applyPolicies exists in the config (#367)

## v2.13.0 (2023-03-05)

### Feat

- implement cache clearing API (#414)

## v2.12.2 (2023-03-05)

### Fix

- get_group_by_path uses Keycloak API to load (#417)

## v2.12.1 (2023-03-05)

### Fix

- tests and upgraded deps (#419)

## v2.12.0 (2023-02-10)

### Feat

- add Keycloak UMA client (#403)

## v2.11.1 (2023-02-08)

### Fix

- do not include CODEOWNERS (#407)

## v2.11.0 (2023-02-08)

### Feat

- Add Client Scopes of Client

## v2.10.0 (2023-02-08)

### Feat

- update header if token is given
- init KeycloakAdmin with token

## v2.9.0 (2023-01-11)

### Feat

- added default realm roles handlers

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

- Support Token Exchange. Fixes #305
- Add get_idp_mappers, fix #329

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

### Feat

- added UMA-permission request functionality

### Fix

- added fixes based on feedback

## v0.28.3 (2022-05-23)

### Fix

- import classes in the base module

## v0.28.2 (2022-05-19)

### Fix

- escape when get role fails

## v0.28.1 (2022-05-19)

### Fix

- Add missing keycloak.authorization package

## v0.28.0 (2022-05-19)

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
