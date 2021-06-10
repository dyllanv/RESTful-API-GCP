from flask import request
from flask import make_response
from flask import session
from google.oauth2 import id_token
from google.auth.transport import requests
from google.cloud import datastore
from __init__ import client
import json
import constants
import secrets


def post_entity(collection, validate, add_entity, format_response, owner_id):
    """
    Uses request to add new boat or load in Datastore.
    Arguments:
        collection - string of collection type (boats/loads)
        validate - function for validating boat or load
        add_entity - function for adding boat or load to Datastore
        format_response - function to format object in JSON
        valid_jwt - valid_jwt['sub'] property needed to:
            - confirm user account exists (in case JWT is still valid,
            but user deleted account).
            - assign ID number to entity
    Returns boat/load object in json, or error message.
    """
    query = client.query(kind=constants.users)
    query.add_filter(constants.id, "=", owner_id)
    results = list(query.fetch())
    if not results:
        return set_response(constants.no_user_exists_error, 401, constants.app_json)

    content = request.get_json()
    # content_validation return = (bool, error response)
    content_invalid = validate(content, False)
    if content_invalid:
        return content_invalid
    new_entity = datastore.entity.Entity(key=client.key(collection))
    add_entity(new_entity, content, owner_id)
    data = format_response(new_entity)
    return set_response(data, 201, constants.app_json)


def get_collection(collection, format_response, valid_jwt=None):
    """
    Get collection of boats/loads
    Arguments:
        entity - boat or load object
        format_response - function to format object in JSON
        valid_jwt - Flag, user has valid jwt. ['sub'] property needed for next page results
    Returns boats/loads object in json, or error message.
    """
    cursor = request.args.get(constants.cursor)
    page = get_one_page(collection, valid_jwt, cursor)
    entity_list = []
    for entry in page[0]:
        entity_list.append(format_response(entry))
    response = {collection: entity_list}
    if page[1]:
        response[constants.next] = "{}?{}={}".format(
            request.url,
            constants.cursor,
            page[1].decode("utf-8")
        )
    return set_response(response, 200, constants.app_json)


def get_single_entity(entity, format_response):
    """
    Get single boat, load, or user information.
    Arguments:
        entity - boat or load object
        format_response - function to format object in JSON
    Returns boat/load/user object in json.
    """
    data = format_response(entity)
    return set_response(data, 200, constants.app_json)


def put_patch_entity(entity, validate, format_response, is_patch):
    """
    Uses request to update ALL boat or load attributes in Datastore.
    Arguments:
        entity - boat or load object
        validate - function for validating boat or load
        format_response - function to format object in JSON
        is_patch - Boolean to differentiate between PUT and PATCH
    Returns boat/load object in json, or error message.
    """
    content = request.get_json()

    # content_validation return = (bool, error response)
    content_invalid = validate(content, is_patch, entity.key.id)
    if content_invalid:
        return content_invalid

    for key in content:
        entity.update({key: content[key]})
    client.put(entity)

    data = format_response(entity)
    return set_response(data, 200, constants.app_json)


def check_id(id_string):
    """Confirm/Convert given id is/too an integer"""
    try:
        id_int = int(id_string)
        return id_int
    except ValueError:
        return False


def validate_request(relational=None):
    """
    Confirm request body is not empty (POST/PUT/PATCH only)
    Confirm the request type and the accept type is JSON.
    GET requests do not need to have a JSON request type.
    DELETE requests do no need to have a JSON request type,
    or a JSON accept type (no response body).
    Arguments:
        relational - Flag, only passed when request is to assign/remove
            a load from a boat. PUT requests in this instance don't
            require a body.

    Returns:
        - Error message if request is invalid
        - None if request is valid
    """
    if request.method in [constants.post, constants.put, constants.patch] and not relational:
        if not request.data:
            return set_response(constants.request_body_empty_error, 400, constants.app_json)
        elif not request.is_json:
            return set_response(constants.must_be_json_error, 415, constants.app_json)
        try:  # Content Type is json, confirms body is valid json
            json.loads(request.data)
        except json.decoder.JSONDecodeError:
            return set_response(constants.invalid_json_error, 400, constants.app_json)

    if constants.app_json not in request.accept_mimetypes \
            and request.method != constants.delete:
        return set_response(constants.accept_mimetype_error, 406, constants.app_json)
    else:
        return None


def get_one_page(kind, valid_jwt, cursor=None):
    """
    Pagination: Get one page of results at a time
    Arguments:
        kind - Collection in Datastore to search
        valid_jwt - Flag, validated user. ['sub'] property is user_id
    Returns: List of items and cursor for next page
    """
    query = client.query(kind=kind)
    if valid_jwt:
        query.add_filter(constants.owner, "=", valid_jwt[constants.sub])
    query_iter = query.fetch(start_cursor=cursor, limit=5)
    page = next(query_iter.pages)

    items = list(page)
    next_cursor = query_iter.next_page_token

    return items, next_cursor


def set_response(data, status_code, mimetype):
    """
    Make response to be returned to used.
    Must set body, mimetype, and status code.
    """
    res = make_response(json.dumps(data))
    res.mimetype = mimetype
    res.status_code = status_code
    return res


def generate_secret():
    """Generate and store secret to be sent/verified for OAuth"""
    secret = secrets.token_urlsafe(16)
    session[constants.current_state] = secret
    return secret


def verify_jwt():
    """
    Verify JSON Web Token
    Argument:
        new_user_jwt - If user
    """
    try:
        if constants.authorization not in request.headers:
            return None
        auth = request.headers[constants.authorization]
        parts = auth.split()  # Part 1: Bearer, Part 2: Token
        if parts[0].lower() != "bearer":
            return None
        jwt = parts[1]

        # Specify the CLIENT_ID of the app that accesses the backend:
        id_info = id_token.verify_oauth2_token(
            jwt,
            requests.Request(),
            constants.client_id
        )
        return id_info
    except ValueError:
        # Invalid token
        return None
