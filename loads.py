from flask import request
from flask import Blueprint
from methods import validate_request
from methods import verify_jwt
from methods import set_response
from methods import get_collection
from methods import post_entity
from methods import check_id
from methods import get_single_entity
from methods import put_patch_entity
from __init__ import client
import constants
import pytz
import datetime


loads_bp = Blueprint('loads', __name__)


@loads_bp.route('/loads', methods=[
    constants.get,
    constants.post,
    constants.put,
    constants.patch,
    constants.delete
])
def loads():
    """Requests for all loads in Datastore"""
    # Confirm the request type and accept types are supported
    invalid_request = validate_request()
    if invalid_request:
        return invalid_request

    # Check for valid JWT
    valid_jwt = verify_jwt()
    if not valid_jwt:
        return set_response(constants.invalid_token_error, 401, constants.app_json)

    elif request.method == constants.get:
        return get_collection(constants.loads, json_load, valid_jwt)

    elif request.method == constants.post:
        return post_entity(constants.loads, validate_load, add_load_entity,
                           json_load, valid_jwt[constants.sub])

    else:
        return set_response(constants.method_not_supported, 405, constants.app_json)


@loads_bp.route('/loads/<load_id>', methods=[
    constants.get,
    constants.post,
    constants.patch,
    constants.put,
    constants.delete
])
def get_put_patch_delete_load(load_id):
    """Requests for specified load in Datastore"""
    # Confirm the request type and accept types are supported
    invalid_request = validate_request()
    if invalid_request:
        return invalid_request

    # Confirm/convert load_id is/to integer
    load_id = check_id(load_id)
    if not load_id:
        return set_response(constants.invalid_id, 400, constants.app_json)

    # Check for valid JWT
    valid_jwt = verify_jwt()
    if not valid_jwt:
        return set_response(constants.invalid_token_error, 401, constants.app_json)

    key = client.key(constants.loads, load_id)
    load = client.get(key=key)
    if not load:
        return constants.no_load_exists_error, 404

    elif load[constants.owner] != valid_jwt[constants.sub]:
        return set_response(constants.user_access_error, 403, constants.app_json)

    elif request.method == constants.get:
        return get_single_entity(load, json_load)

    elif request.method == constants.put:
        return put_patch_entity(load, validate_load, json_load, False)

    elif request.method == constants.patch:
        return put_patch_entity(load, validate_load, json_load, True)

    elif request.method == constants.delete:
        return delete_load(key)

    else:
        return set_response(constants.method_not_supported, 405, constants.app_json)


def delete_load(key):
    """Delete load from Datastore"""
    client.delete(key)
    return set_response('', 204, constants.app_json)


def add_load_entity(load, content, owner_id):
    """Adds load in Datastore"""
    content[constants.carrier] = None
    content[constants.creation_date] = \
        str(datetime.datetime.now(pytz.timezone("US/Pacific")).date())
    load.update({
        constants.volume: content[constants.volume],
        constants.carrier: content[constants.carrier],
        constants.content: content[constants.content],
        constants.creation_date: content[constants.creation_date],
        constants.owner: owner_id
    })
    client.put(load)


def validate_load(content, is_patch, load_id=None):
    """Validate load content"""
    if len(content) > 2:
        return set_response(constants.too_many_attributes_error, 400, constants.app_json)
    for attribute in content:
        if attribute not in [constants.volume, constants.content]:
            return set_response(constants.unexpected_attribute_error, 400, constants.app_json)

    if not is_patch \
            and (constants.volume not in content or constants.content not in content):
        return set_response(constants.attribute_missing_error, 400, constants.app_json)

    elif constants.volume in content \
            and not validate_volume(content[constants.volume]):
        return set_response(constants.invalid_volume, 400, constants.app_json)

    elif constants.content in content \
            and not validate_content(content[constants.content]):
        return set_response(constants.invalid_content, 400, constants.app_json)

    else:
        return None


def validate_volume(volume):
    """
    Validate load volume:
    Must be int in range 1 - 10000
    """
    if type(volume) is not int:
        return False
    elif volume > 10000 or volume < 1:
        return False
    else:
        return True


def validate_content(content):
    """
    Validate load content:
    Must be string of 3 - 50 characters
    """
    if type(content) is not str:
        return False
    elif len(content) > 50 or len(content) < 3:
        return False
    return True


def json_load(load):
    """
    Format response in JSON:
    If load has a carrier boat, display basic boat info.
    """
    response = {
        constants.id: load.key.id,
        constants.volume: load[constants.volume],
        constants.carrier: None,
        constants.content: load[constants.content],
        constants.creation_date: load[constants.creation_date],
        constants.owner: load[constants.owner],
        constants.self: constants.self_link_format.format(
            request.url_root,
            constants.loads,
            str(load.key.id)
        )
    }
    if load[constants.carrier]:
        boat_key = client.key(constants.boats, int(load[constants.carrier]))
        boat = client.get(key=boat_key)
        response[constants.carrier] = {
            constants.id: boat.key.id,
            constants.name: boat[constants.name],
            constants.self: constants.self_link_format.format(
                request.url_root,
                constants.boats,
                str(boat.key.id)
            )
        }
    return response
