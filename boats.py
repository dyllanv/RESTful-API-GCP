from flask import request
from flask import Blueprint
import constants
from methods import validate_request
from methods import verify_jwt
from methods import set_response
from methods import get_collection
from methods import post_entity
from methods import check_id
from methods import get_single_entity
from methods import put_patch_entity
from __init__ import client
from loads import json_load

boats_bp = Blueprint('boats', __name__)


@boats_bp.route('/boats', methods=[
    constants.get,
    constants.post,
    constants.put,
    constants.patch,
    constants.delete
])
def boats():
    """Requests for all boats in Datastore"""
    # Confirm the request type and accept types are supported
    invalid_request = validate_request()
    if invalid_request:
        return invalid_request

    # Check for valid JWT
    valid_jwt = verify_jwt()
    if not valid_jwt:
        return set_response(constants.invalid_token_error, 401, constants.app_json)

    elif request.method == constants.get:
        return get_collection(constants.boats, json_boat, valid_jwt)

    elif request.method == constants.post:
        return post_entity(constants.boats, validate_boat, add_boat_entity, json_boat, valid_jwt[constants.sub])

    else:
        return set_response(constants.method_not_supported, 405, constants.app_json)


@boats_bp.route('/boats/<boat_id>', methods=[
    constants.get,
    constants.post,
    constants.patch,
    constants.put,
    constants.delete
])
def get_put_patch_delete_boat(boat_id):
    """Requests for specified boat in Datastore"""
    # Confirm the request type and accept types are supported
    invalid_request = validate_request()
    if invalid_request:
        return invalid_request

    # Confirm/convert boat_id is/to integer
    boat_id = check_id(boat_id)
    if not boat_id:
        return set_response(constants.invalid_id, 400, constants.app_json)

    # Check for valid JWT
    valid_jwt = verify_jwt()
    if not valid_jwt:
        return set_response(constants.invalid_token_error, 401, constants.app_json)

    key = client.key(constants.boats, boat_id)
    boat = client.get(key=key)
    if not boat:
        return constants.no_boat_exists_error, 404

    elif boat[constants.owner] != valid_jwt[constants.sub]:
        return set_response(constants.user_access_error, 403, constants.app_json)

    elif request.method == constants.get:
        return get_single_entity(boat, json_boat)

    elif request.method == constants.put:
        return put_patch_entity(boat, validate_boat, json_boat, False)

    elif request.method == constants.patch:
        return put_patch_entity(boat, validate_boat, json_boat, True)

    elif request.method == constants.delete:
        return delete_boat(key)

    else:
        return set_response(constants.method_not_supported, 405, constants.app_json)


@boats_bp.route('/boats/<boat_id>/loads', methods=[
    constants.get,
    constants.post,
    constants.patch,
    constants.put,
    constants.delete
])
def boat_loads(boat_id):
    """
    Get all loads assigned to a given boat.
    """
    if request.method != constants.get:
        return set_response(constants.method_not_supported, 405, constants.app_json)

    # Confirm the request type and accept types are supported
    invalid_request = validate_request()
    if invalid_request:
        return invalid_request

    # Confirm/convert boat_id is/to integer
    boat_id = check_id(boat_id)
    if not boat_id:
        return set_response(constants.invalid_id, 400, constants.app_json)

    # Check for valid JWT
    valid_jwt = verify_jwt()
    if not valid_jwt:
        return set_response(constants.invalid_token_error, 401, constants.app_json)

    boat_key = client.key(constants.boats, boat_id)
    boat = client.get(key=boat_key)
    if not boat:
        return set_response(constants.no_boat_exists_error, 404, constants.app_json)

    elif boat[constants.owner] != valid_jwt[constants.sub]:
        return set_response(constants.user_access_error, 403, constants.app_json)

    query = client.query(kind=constants.loads)
    query.add_filter(constants.carrier, "=", boat_id)
    results = list(query.fetch())
    response = []
    for entry in results:
        response.append(json_load(entry))
    return set_response(response, 200, constants.app_json)


@boats_bp.route('/boats/<boat_id>/loads/<load_id>', methods=[
    constants.get,
    constants.post,
    constants.patch,
    constants.put,
    constants.delete
])
def boat_loads_put_delete(boat_id, load_id):
    """Allow boat user to assign a load to their boat"""
    if request.method not in [constants.put, constants.delete]:
        return set_response(constants.method_not_supported, 405, constants.app_json)

    # Confirm the accept type is supported
    invalid_request = validate_request(True)
    if invalid_request:
        return invalid_request

    # Confirm/convert boat_id and load_id is/to integer
    boat_id = check_id(boat_id)
    load_id = check_id(load_id)
    if not boat_id or not load_id:
        return set_response(constants.invalid_id, 400, constants.app_json)

    # Check for valid JWT
    valid_jwt = verify_jwt()
    if not valid_jwt:
        return set_response(constants.invalid_token_error, 401, constants.app_json)

    load_key = client.key(constants.loads, load_id)
    load = client.get(key=load_key)
    boat_key = client.key(constants.boats, boat_id)
    boat = client.get(key=boat_key)
    if not load and not boat:
        return set_response(constants.no_boat_or_load_error, 404, constants.app_json)
    elif not load:
        return set_response(constants.no_load_exists_error, 404, constants.app_json)
    elif not boat:
        return set_response(constants.no_boat_exists_error, 404, constants.app_json)

    elif boat[constants.owner] != valid_jwt[constants.sub]:
        return set_response(constants.user_access_error, 403, constants.app_json)

    elif request.method == constants.put:
        if load[constants.carrier]:
            return set_response(constants.load_already_assigned_error, 403, constants.app_json)
        load.update({constants.carrier: boat_id})
        client.put(load)
        return set_response('', 204, constants.app_json)

    elif request.method == constants.delete:
        if load[constants.carrier] != boat_id:
            return set_response(constants.load_not_on_boat_error, 404, constants.app_json)
        load.update({constants.carrier: None})
        client.put(load)
        return set_response('', 204, constants.app_json)

    else:
        return set_response(constants.method_not_supported, 405, constants.app_json)


def delete_boat(key):
    """Delete boat from Datastore"""
    query = client.query(kind=constants.loads)
    query.add_filter(constants.carrier, "=", key.id)
    results = list(query.fetch())
    for entry in results:
        entry.update({constants.carrier: None})
        client.put(entry)
    client.delete(key)
    return set_response('', 204, constants.app_json)


def add_boat_entity(boat, content, owner_id):
    """Adds boat in Datastore"""
    boat.update({
        constants.name: content[constants.name],
        constants.type: content[constants.type],
        constants.length: content[constants.length],
        constants.owner: owner_id
    })
    client.put(boat)


def validate_boat(content, is_patch, boat_id=None):
    """
    Validates content in POST/PUT/PATCH requests
    POST/PUT: Must contain all boat attributes
    PATCH: Can contain any combination of attributes
    """
    if len(content) > 3:
        return set_response(constants.too_many_attributes_error, 400, constants.app_json)

    for attribute in content:
        if attribute not in [constants.name, constants.type, constants.length]:
            return set_response(constants.unexpected_attribute_error, 400, constants.app_json)

    if not is_patch and (
            constants.name not in content
            or constants.type not in content
            or constants.length not in content):
        return set_response(constants.attribute_missing_error, 400, constants.app_json)

    elif constants.name in content \
            and not validate_name_type(content[constants.name]):
        return set_response(constants.invalid_name, 400, constants.app_json)

    elif constants.name in content \
            and not name_is_unique(content[constants.name], boat_id):
        return set_response(constants.boat_name_exists, 403, constants.app_json)

    elif constants.type in content \
            and not validate_name_type(content[constants.type]):
        return set_response(constants.invalid_type, 400, constants.app_json)

    elif constants.length in content \
            and not validate_length(content[constants.length]):
        return set_response(constants.invalid_length, 400, constants.app_json)

    else:
        return None


def validate_name_type(attribute):
    """
    Validates name and type attributes of boat.
    Must be string type.
    Must be 2-25 characters.
    Must start with a letter.
    Must end with a letter or number.
    May contain blank space and one of the following special characters:
        ./-
    """
    if type(attribute) is not str:
        return False
    elif len(attribute) > 25 or len(attribute) < 2:
        return False
    elif not attribute[0].isalpha() or not attribute[-1].isalnum():
        return False
    for char in attribute:
        if not char.isalnum() and char not in constants.special_characters:
            return False
    return True


def validate_length(length):
    """
    Validates length attribute of boat.
    Must be integer.
    Must be in range 3-2000.
    """
    if type(length) is not int:
        return False
    elif length > 2000 or length < 3:
        return False
    else:
        return True


def name_is_unique(name, boat_id=None):
    """Confirms name from POST/PUT/PATCH request is unique"""
    query = client.query(kind=constants.boats)
    query.add_filter(constants.name, "=", name)
    results = list(query.fetch())
    if boat_id and len(results) == 1 and boat_id == results[0].key.id:
        return True
    elif not results:
        return True
    else:
        return False


def json_boat(boat):
    """
    Format response in JSON:
    Display basic info for boat and each load carried on the boat.
    """
    response = {
        constants.id: boat.key.id,
        constants.name: boat[constants.name],
        constants.type: boat[constants.type],
        constants.length: boat[constants.length],
        constants.owner: boat[constants.owner],
        constants.loads: [],
        constants.self: constants.self_link_format.format(
            request.url_root,
            constants.boats,
            str(boat.key.id)
        )
    }
    query = client.query(kind=constants.loads)
    query.add_filter(constants.carrier, "=", boat.key.id)
    load_results = list(query.fetch())
    for entry in load_results:
        response[constants.loads].append({
            constants.id: entry.key.id,
            constants.self: constants.self_link_format.format(
                request.url_root,
                constants.loads,
                str(entry.key.id)
            )
        })
    return response


@boats_bp.route('/test', methods=[constants.get, constants.delete])
def test():
    query = client.query(kind=constants.boats)
    results = list(query.fetch())
    if request.method == constants.get:
        boat_list = []
        for entry in results:
            boat_list.append(json_boat(entry))
        return set_response(boat_list, 200, constants.app_json)
    else:
        for entry in results:
            client.delete(entry.key)
        return set_response('', 204, constants.app_json)
