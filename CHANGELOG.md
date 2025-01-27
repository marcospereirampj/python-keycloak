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
- Changes the exchange token API
- Renamed parameter client_name to client_id in get_client_id method
- Renames `KeycloakOpenID.well_know` to `KeycloakOpenID.well_known`

### Feat

- add more request
- get_client_all_sessions now supports pagination
- uma extra payload
- user profile metadata parameter for get_user method
- uma extra payload
- add client scope client-specific role mappings (#605)
- Add the max_retries parameter (#598)
- add ability to remove composite client roles (#596)
- add matchingUri support for listing resources with wildcards (#592)
- allow the use of client certificates in all requests (#584)
- functions for updating resource permissions and getting associated policies for a permission (#574)
- Async feature (#566)
- Merge pull request #556 from marcospereirampj/release/4.0.0
- re-enable full group hierarchy fetching
- allows retrieval of realm and client level roles for a user (#512)
- add admin group count (#540)
- Allow query parameters for group children (#534)
- new docs.
- new docs.
- new docs.
- new docs.
- new docs.
- new docs.
- new docs.
- Adding additional methods to support roles-by-id api calls Most of the methods rely on the role name within python keycloak, which for the vast majority is fine, however there are some role names which cannot be used by the API endpoint as they contain characters that cannot be encoded properly. Therefore this change is to allow the use of the role's id to get, update and delete roles by their id instead.'
- realm changing helpers
- add KeycloakAdmin.get_idp() (#478)
- Update dynamic client using registration access token (#491)
- add an optional search criteria to the get_realm_roles function (#504)
- added KeycloakAdmin.update_client_authz_resource() (#462)
- Implement missing admin method create_client_authz_scope_based_permission() and create_client_authz_policy() (#460)
- Add query to get users group method and permit pagination (#444)
- Add get and delete methods for client authz resources (#435)
- Add UMA policy management and permission tickets (#426)
- add initial access token support and policy delete method
- implement cache clearing API (#414)
- add Keycloak UMA client (#403)
- Add Client Scopes of Client
- update header if token is given
- init KeycloakAdmin with token
- added default realm roles handlers
- **api**: add tests for create_authz_scopes
- option for enabling users
- helping functions for disabling users
- attack detection API implementation
- added missing functionality to include attributes when returning realm roles according to specifications
- add client scope-mappings client roles operations
- Add token_type/scope to token exchange api
- add client scope-mappings realm roles operations
- add unit tests
- add docstrings
- add functions covering some missing REST API calls
- added flake8-docstrings and upgraded dependencies
- Ability to set custom timeout for KCOpenId and KCAdmin
- Allow fetching existing policies before calling create_client_authz_client_policy()
- support token exchange config via admin API
- Add update_idp
- Add update_mapper_in_idp
- Support Token Exchange. Fixes #305
- Add get_idp_mappers, fix #329
- added new methods for client scopes
- added UMA-permission request functionality
- added authenticator providers getters
- fixed admin client to pass the tests
- initial setup of CICD and linting
- add KeycloakAdmin.set_events
- add components

### Fix

- retry upon 401
- check uma permissions with resource ID as well
- get group by path should not raise on 404
- change to mounts (#622)
- Feature parity for `a_decode_token` and `decode_token` (#616)
- make sure to not call sync IO functions inside async functions (#615)
- Add optional Nonce parameter to the authorization URL requests (#606)
- add scopes to device auth (#599)
- changed sync get user id to async get user in create user async function (#600)
- Set client_credentials as grant_type also when x509 certificate is given (#597)
- use a_public_key() in a_decode_token() instead of public_key() (#582)
- correctly pass query params in a_send_update_account and a_send_verify_email (#581)
- passing timeout values to ConnectionManager (#578)
- Leeway config (#568)
- removed dead code, stabilized tests
- removed deprecated functionality
- lowercase default role name (#547)
- fix keycloak_admin.create_user documentation/ typehint (#545)
- improve KeycloakAdmin.get_client_id() performances (#511)
- incorporate custom headers into default header setup (#533)
- get_groups pagination call was not used #537 (#541)
- use jwcrypto and remove python-jose
- replace python-jose with jwcrypto
- updated readme.
- use grant type password with client secret
- name of client_id parameter
- update readme.
- linter check
- updated dependencies
- Removing the admin realm variable which I created and is no longer needed
- action bump
- linter check.
- depracated endpoint and fix groups services.
- deprecate entitlement
- no prints
- Ci/fix tests (#506)
- remove duplicate slash in URL_ADMIN_IDP (#459)
- relax the version constraints
- do not swap realm for user_realm when logging in with a client service account (#447)
- Fixes `Authorization.load_config` breaking if a scope based permission is linked with anything other than a role based policy. Fixes #445 (#446)
- issue with app engine reported in #440 (#442)
- Initializing KeycloakAdmin without server_url (#439)
- **pyproject.toml**: loose requests pgk and remove urllib3 as dependency (#434)
- Check if _s exists in ConnectionManager before deleting it (#429)
- deprecation warnings in keycloak_admin.py (#425)
- improved type-hints (#427)
- Refactor auto refresh (#415)
- Check if applyPolicies exists in the config (#367)
- get_group_by_path uses Keycloak API to load (#417)
- tests and upgraded deps (#419)
- do not include CODEOWNERS (#407)
- fix testing create_client_authz_scopes parameters
- fix linting
- add testcase for invalid client id
- create authz clients test case
- create authz clients test case
- use version from the package
- default scope to openid
- removed whitespace from urls
- linting
- now get_required_action_by_alias now returns None if action does not exist
- moved imports at the top of the file
- remove duplicate function
- applied tox -e docs
- applied flake linting checks
- applied tox linting check
- check client existence based on clientId
- turn get_name into a method, use setters in connection manager
- Support the auth_url method called with scope & state params now
- raise correct exceptions
- fixed bugs in events methods
- fixed components bugs
- use param for update client mapper
- allow query parameters for users count
- correct spelling of public API method
- allow client_credentials token if username and password not specified
- added fixes based on feedback
- import classes in the base module
- escape when get role fails
- Add missing keycloak.authorization package
- full tox fix ready
- raise correct errors
- **release**: version bumps for hotfix release
- handle refresh_token error "Session not active"

### Refactor

- refactored decode_token
- Exchange token method
- code formatting after tox checks
- remove print statements
- applied linting
- no need to try if the type check is performed
- merge master branch into local
- slight restructure of the base fixtures
- isort conf.py
- Merge branch 'master' into feature/cicd

### Perf

- improve performance of get_user_id (#449)
