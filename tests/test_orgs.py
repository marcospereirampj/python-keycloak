from keycloak import KeycloakAdmin
import json

# Keycloak Configuration
KEYCLOAK_URL = "https://auth.illysky.io"
REALM_NAME = "cassandra"
CLIENT_ID = "administration"
CLIENT_SECRET = "JMFYMbWfPBYG3t6C4ZtQ5tfXjBE6n2PY"  


keycloak_admin = KeycloakAdmin(
    server_url=f"{KEYCLOAK_URL}/",
    realm_name=REALM_NAME,
    client_id=CLIENT_ID,
    client_secret_key=CLIENT_SECRET,
    verify=True  
)



# 🟢 Test fetching all organizations
print("\n🔹 Fetching all organizations...")
organizations = keycloak_admin.get_organizations()
print(json.dumps(organizations, indent=4))

# 🟢 Test creating an organization
print("\n🔹 Creating a new organization...")
new_org = {"name": "St Leonards Academy", "alias": "st-leonards-academy", "description": "This is a test organization", "domains": ["test.com"]}
keycloak_admin.create_organization(new_org)
print("Created Organization")

# 🟢 Test fetching all organizations
print("\n🔹 Fetching all organizations...")
organizations = keycloak_admin.get_organizations()
print(json.dumps(organizations, indent=4))
organization_id = next((org["id"] for org in organizations if org["name"] == new_org["name"]), None)


# 🟢 Test fetching organization details
print(f"\n🔹 Fetching organization details for {organization_id}...")
org_details = keycloak_admin.get_organization(organization_id)
print(org_details)

# 🟢 Test updating organization
print("\n🔹 Updating organization...")



# 🟢 Test listing organization members
print("\n🔹 Fetching members of the organization...")
org_members = keycloak_admin.get_organization_members(organization_id)
print(json.dumps(org_members, indent=4))

# 🟢 Test adding a user to an organization
user_id = "e9dc913d-9d55-4e01-b70b-4cf5d3b3393a"  # Replace with a real user ID
print(f"\n🔹 Adding user {user_id} to organization {organization_id}...")
add_response = keycloak_admin.add_user_to_organization(organization_id, user_id)
print("Added User")


# 🟢 Test listing organization members
print("\n🔹 Fetching members of the organization...")
org_members = keycloak_admin.get_organization_members(organization_id)
print(json.dumps(org_members, indent=4))

# 🟢 Test removing a user from an organization
print(f"\n🔹 Removing user {user_id} from organization {organization_id}...")
remove_response = keycloak_admin.remove_user_from_organization(organization_id, user_id)
print("Removed User Response:", remove_response)

# 🟢 Test deleting an organization
print("\n🔹 Deleting organization...")
delete_response = keycloak_admin.delete_organization(organization_id)
print("Deleted Organization Response:", delete_response)
