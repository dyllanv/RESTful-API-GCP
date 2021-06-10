from flask import request
from flask import Blueprint
import constants
import threading
from methods import validate_request
from methods import verify_jwt
from methods import set_response
from methods import get_collection
from methods import check_id
from methods import get_single_entity
from __init__ import client


users_bp = Blueprint('users', __name__)


@users_bp.route('/users', methods=[
    constants.get,
    constants.post,
    constants.put,
    constants.patch,
    constants.delete
])
def users():
    """Requests for all users in Datastore"""
    # Confirm the request type and accept types are supported
    invalid_request = validate_request()
    if invalid_request:
        return invalid_request
    elif request.method == constants.get:
        return get_collection(constants.users, json_user)
    else:
        return set_response(constants.method_not_supported, 405, constants.app_json)


@users_bp.route('/users/<user_id>', methods=[
    constants.get,
    constants.post,
    constants.put,
    constants.patch,
    constants.delete
])
def get_delete_user(user_id):
    """Requests for all users in Datastore"""
    # Confirm the request type and accept types are supported
    invalid_request = validate_request()
    if invalid_request:
        return invalid_request

    # user_id CANNOT be converted to int, throws Value out of range error
    # Store/keep as string
    if not check_id(user_id):
        return set_response(constants.invalid_id, 400, constants.app_json)

    # Check for valid JWT
    valid_jwt = verify_jwt()
    if not valid_jwt:
        return set_response(constants.invalid_token_error, 401, constants.app_json)
    jwt_user_id = valid_jwt[constants.sub]

    query = client.query(kind=constants.users)
    query.add_filter(constants.id, "=", user_id)
    results = list(query.fetch())
    if not results:
        return set_response(constants.no_user_exists_error, 404, constants.app_json)
    elif user_id != jwt_user_id:
        return set_response(constants.user_access_error, 403, constants.app_json)
    elif request.method == constants.get:
        return get_single_entity(results[0], json_user)
    elif request.method == constants.delete:
        return delete_user(results[0])
    else:
        return set_response(constants.method_not_supported, 405, constants.app_json)


def delete_user(user):
    """
    Delete user from Datastore
    Thread 1: Add all associated boats to key_list.
    Thread 2: Add all associated loads to key_list.
    Thread 3: Delete user.
    **Note**
        Do not delete loads in thread
    """
    # creating threads
    key_list = []
    t1 = threading.Thread(
        target=delete_user_boats,
        args=(user[constants.id], key_list),
        name='t1'
    )
    t2 = threading.Thread(
        target=delete_user_loads,
        args=(user[constants.id], key_list),
        name='t2'
    )
    t3 = threading.Thread(
        target=delete_user_entity,
        args=(user[constants.id],),
        name='t3'
    )

    # starting threads
    t1.start()
    t2.start()
    t3.start()

    # wait until all threads finish
    t1.join()
    t2.join()
    t3.join()

    client.delete_multi(key_list)

    return set_response('', 204, constants.app_json)


def delete_user_boats(user_id, key_list):
    """
    Thread: Add all boats associated with user to key_list
    Update all loads carried by each boat to have a 'carrier' of None/null
    """
    # Delete all boats associated with User
    query = client.query(kind=constants.boats)
    query.add_filter(constants.owner, "=", user_id)
    results = list(query.fetch())
    for bt in results:
        query = client.query(kind=constants.loads)
        query.add_filter(constants.owner, "=", user_id)
        loads_on_boat = list(query.fetch())
        for ld in loads_on_boat:
            ld.update({constants.carrier: None})

        key_list.append(bt.key)


def delete_user_loads(user_id, key_list):
    """Thread: Add all loads associated with user to key_list"""
    # Delete all loads associated with User
    query = client.query(kind=constants.loads)
    query.add_filter(constants.owner, "=", user_id)
    results = list(query.fetch())
    for ld in results:
        key_list.append(ld.key)


def delete_user_entity(user_id):
    """Delete user entity"""
    query = client.query(kind=constants.users)
    query.add_filter(constants.id, "=", user_id)
    user = list(query.fetch())
    client.delete(user[0].key)


def update_user_entity(user, data):
    """Updates user in Datastore"""
    user.update({
        constants.id:
            data[constants.names][0][constants.metadata][constants.source][constants.id],
        constants.given_name: data[constants.names][0][constants.givenName],
        constants.family_name: data[constants.names][0][constants.familyName]
    })
    client.put(user)


def json_user(user):
    """
    Format response in JSON:
    Thread 1: Request all boats associated with user, format for display.
    Thread 2: Request all loads associated with user, format for display.
    """
    response = {
        constants.id: user[constants.id],
        constants.given_name: user[constants.given_name],
        constants.family_name: user[constants.family_name],
        constants.boats: [],
        constants.loads: [],
        constants.self: constants.self_link_format.format(
            request.url_root,
            constants.users,
            str(user[constants.id])
        )
    }

    # creating threads
    t1 = threading.Thread(
        target=json_user_collection,
        args=(user[constants.id], response, request.url_root, constants.boats),
        name='t1'
    )
    t2 = threading.Thread(
        target=json_user_collection,
        args=(user[constants.id], response, request.url_root, constants.loads),
        name='t2'
    )

    # starting threads
    t1.start()
    t2.start()

    # wait until all threads finish
    t1.join()
    t2.join()

    return response


def json_user_collection(user_id, response, request_url, collection):
    """Thread to request and populate user list of boats (in response dict)"""
    query = client.query(kind=collection)
    query.add_filter(constants.owner, "=", user_id)
    results = list(query.fetch())
    for entry in results:
        response[collection].append({
            constants.id: entry.key.id,
            constants.self: constants.self_link_format.format(
                request_url,
                collection,
                str(entry.key.id)
            )
        })
