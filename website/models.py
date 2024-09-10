import time
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)

import logging
import gssapi

db = SQLAlchemy()

logger = logging.getLogger(__name__)

SERVER_NAME = gssapi.Name('FOSDEM.ORG@')  # Server's principal name

class User:
    def __init__(self, username):
        self.user_id = username
    
    def get_user_id(self):
        return self.user_id

    def check_password(self, password):
        user = gssapi.Name(base=self.user_id, name_type=gssapi.NameType.user)
        bpass = password.encode('utf-8')
        try:
            creds_wrapper = gssapi.raw.acquire_cred_with_password(user, bpass, usage='initiate')
            creds = creds_wrapper.creds  # Extract the credentials from the wrapper

            # Initialize a security context with the server's principal and user's credentials
            context = gssapi.SecurityContext(name=SERVER_NAME, creds=creds, usage='initiate')
            return True  # If no exception occurs, authentication is successful

        except gssapi.exceptions.GSSError as er:
            logger.debug(f"Kerberos authentication failed: {er}")
            return False
        except AttributeError:
            logger.debug("An AttributeError occurred.")
            return False


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(40), nullable=False)

    @property
    def user(self):
        return User(self.user_id) 


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(40), nullable=False)

    @property
    def user(self):
        return User(self.user_id) 

class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(40), nullable=False)

    @property
    def user(self):
        return User(self.user_id) 

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
