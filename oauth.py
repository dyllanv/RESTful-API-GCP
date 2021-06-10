from flask import request
from flask import redirect
from flask import render_template
from flask import session
from flask import Blueprint
from google.cloud import datastore
from urllib import request as url_request
from __init__ import client
from methods import generate_secret
from methods import set_response
from users import json_user
from users import update_user_entity
import json
import constants


oauth_bp = Blueprint('oauth', __name__, template_folder='templates')


@oauth_bp.route('/', methods=[constants.get])
def root():
    """Home Page with link to /oauth route"""
    return render_template("index.html")


@oauth_bp.route('/oauth', methods=[constants.get])
def oauth():
    """
    First request: Redirect to Google API to receive authorization code.
        generate/store secret state to be sent, redirect back to this route.
    After redirect: Confirm received state matches session current_state,
        Send POST request with auth code to get auth token, then send GET request
        to get user's name to be displayed.
    """
    if constants.code not in request.args:
        auth_uri = ("https://accounts.google.com/o/oauth2/v2/auth?client_id={}"
                    "&redirect_uri={}&response_type=code&scope=profile&"
                    "state={}&access_type=offline ").format(
            constants.client_id,
            request.url_root + "oauth",
            generate_secret()
        )
        return redirect(auth_uri)
    else:
        current_state = session.get(constants.current_state)
        if not current_state or not current_state == request.args.get("state"):
            return set_response(constants.state_error, 401, constants.app_json)
        url = ("{}?client_id={}&client_secret={}&code={}&grant_type={}"
               "&redirect_uri={}oauth").format(
            constants.token_url, constants.client_id, constants.client_secret,
            request.args.get(constants.code), constants.grant_type, request.url_root
        )
        # res = requests.post(url)
        req = url_request.Request(url, method=constants.post)
        res = url_request.urlopen(req)
        data = json.load(res)
        jwt = data["id_token"]

        req = url_request.Request(constants.get_url)
        req.add_header(
            constants.authorization,
            "{} {}".format(data["token_type"],
                           data["access_token"])
        )
        res = url_request.urlopen(req)
        data = json.load(res)

        # Check to see if user already exists
        query = client.query(kind=constants.users)
        query.add_filter(constants.id, "=",
                         data[constants.names][0][constants.metadata][constants.source][constants.id]
                         )
        results = list(query.fetch())
        if results:
            user = results[0]
        else:
            # New user
            user = datastore.entity.Entity(key=client.key(constants.users))
        update_user_entity(user, data)
        data = json_user(user)

        return render_template("oauth.html",
                               fname=data[constants.given_name],
                               lname=data[constants.family_name],
                               jwt=jwt,
                               id=data[constants.id]
                               )
