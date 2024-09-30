from dataclasses import dataclass
import time
import yaml
from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)

import logging
import gssapi

db = SQLAlchemy()

logger = logging.getLogger(__name__)

class User:
    def __init__(self, username):
        self.user_id = username
        self.extra_info = current_app.config.get('USER_INFO').get(username, None)
        self.realm = current_app.config.get('REALM')

    def get_user_id(self):
        return self.user_id

    def check_password(self, password):
        user = gssapi.Name(
            base=f"{self.user_id}@{self.realm}", name_type=gssapi.NameType.user
        )
        bpass = password.encode("utf-8")
        try:
            creds_wrapper = gssapi.raw.acquire_cred_with_password(
                user, bpass, usage="initiate"
            )
            creds = creds_wrapper.creds  # Extract the credentials from the wrapper

            # Initialize a security context with the server's principal and user's credentials
            context = gssapi.SecurityContext(
                name=f"{self.realm}@", creds=creds, usage="initiate"
            )

            return True  # If no exception occurs, authentication is successful

        except gssapi.exceptions.GSSError as er:
            logger.info(f"Kerberos authentication failed: {er}")
            print(er)
            return False


@dataclass
class OAuth2Client:
    client_id: str
    client_secret: str
    client_name: str
    token_endpoint_auth_method: str
    redirect_uris: list

    def check_client_secret(self, client_secret):
        return client_secret == self.client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        return method == self.token_endpoint_auth_method

    def check_grant_type(self, grant_type):
        # we only support authorization code
        return grant_type == "authorization_code"

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def check_response_type(self, response_type):
        return response_type in ["code"]

    def get_allowed_scope(self, scope):
        return "profile"


@dataclass
class Userinfo:
    """Store extra userinfo such as groups"""

    groups: list
    full_name: str





class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_code"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(40), nullable=False)

    @property
    def user(self):
        return User(self.user_id)


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = "oauth2_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(40), nullable=False)

    @property
    def user(self):
        return User(self.user_id)

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
