# Supported Methods
get = "GET"
post = "POST"
put = "PUT"
patch = "PATCH"
delete = "DELETE"

# Boats and boat attributes
boats = "boats"
name = "name"
type = "type"
length = "length"
public = "public"
owner = "owner"

# Loads and load attributes
loads = "loads"
volume = "volume"
content = "content"
creation_date = "creation_date"
carrier = "carrier"

# Users and user attributes
users = "users"
given_name = "given_name"
family_name = "family_name"

# OAUTH CONSTANTS
client_id = "TOP SECRET CLIENT ID"
client_secret = "SUPER SECRET CLIENT SECRET"
grant_type = "authorization_code"
response_type = "code"
scope = "profile"
current_state = "current_state"
code = "code"
sub = "sub"  # JWT property used as user_id
authorization = "Authorization"
token_url = "https://oauth2.googleapis.com/token"

# Properties to access from Google People API with OAuth token
get_url = "https://people.googleapis.com/v1/people/me?personFields=names"
givenName = "givenName"
familyName = "familyName"
names = "names"
metadata = "metadata"
source = "source"

# Miscellaneous strings
self = "self"
self_link_format = "{}{}/{}"
id = "id"
next = "next"
cursor = "cursor"

# Generic 400 Errors
request_body_empty_error = {"Error": "The request body must not be empty."}
unexpected_attribute_error = {"Error": "Unexpected attribute in request."}
attribute_missing_error = {"Error": "The request object is missing "
                                    "at least one of the required attributes"}
too_many_attributes_error = {"Error": "The request contains too "
                                      "many attributes."}
invalid_json_error = {"Error": "Invalid JSON in request body"}
invalid_id = {"Error": "Invalid ID number"}

# Boat 400 Errors
invalid_name = {"Error": "Invalid boat name"}
invalid_type = {"Error": "Invalid boat type"}
invalid_length = {"Error": "Invalid boat length"}

# Load 400 Errors
invalid_volume = {"Error": "Invalid load volume"}
invalid_content = {"Error": "Invalid load content"}

# 401 Errors
invalid_token_error = {"Error": "Invalid JWT"}
# State Error: State sent for OAuth not recognized on return (security issue)
state_error = {"Error": "No idea how, but the state doesn't match."}

# 403 Errors
load_already_assigned_error = {"Error": "This load is already assigned "
                                        "to a boat"}
boat_name_exists = {"Error": "Boat name already exists"}
user_access_error = {"Error": "This user does not have access to "
                              "this resource."}

# 404 Errors
no_boat_exists_error = {"Error": "No boat with this boat_id exists"}
no_load_exists_error = {"Error": "No load with this load_id exists"}
no_boat_or_load_error = {"Error": "Neither the boat nor load with the"
                                  " given IDs exist"}
no_user_exists_error = {"Error": "No user with this user_id exists"}
load_not_on_boat_error = {"Error": "No load with this load_id is on"
                                   " the boat with this boat_id"}

# 405 Error
method_not_supported = {"Error": "Method not supported."}

# 406 Error
accept_mimetype_error = {"Error": "Requested response type not supported"}

# 415 Error
must_be_json_error = {"Error": "Request must be in JSON"}

special_characters = "-/.' "
app_json = "application/json"
text_html = "text/html"
