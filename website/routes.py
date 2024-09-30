import time
import logging
from flask import Blueprint, request, session, url_for
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth, clients


bp = Blueprint("home", __name__)

logger = logging.getLogger(__name__)


def current_user():
    if "id" in session:
        username = session["id"]
        return User(username)
    return None


@bp.route("/", methods=("GET", "POST"))
def home():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User(username=username, realm="NORDU.NET")
        if user.check_password(password):
            session["id"] = username
            # if user is not just to log in, but need to head back to the auth page, then go for it
            next_page = request.args.get("next")
            if next_page:
                return redirect(next_page)
            return redirect("/")
        else:
            logger.info("login failed - username: {{ username }}")
    user = current_user()

    return render_template("home.html", user=user, clients=clients)


@bp.route("/logout")
def logout():
    del session["id"]
    return redirect("/")


@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    user = current_user()
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for("home.home", next=request.url))
    if request.method == "GET":
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template("authorize.html", user=user, grant=grant)
    if not user and "username" in request.form:
        username = request.form.get("username")
        password = request.form.get("password")
        user = User(username=username)
        user.check_password(password)
    if "confirm" in request.form and request.form["confirm"]:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    return authorization.create_token_response()


@bp.route("/oauth/revoke", methods=["POST"])
def revoke_token():
    return authorization.create_endpoint_response("revocation")


@bp.route("/api/me")
@require_oauth("profile")
def api_me():
    user = current_token.user

    return jsonify(username=user.user_id, extra_info=user.extra_info)
