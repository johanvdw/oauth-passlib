
import yaml
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import UserInfo
from flask import current_app
from .models import db, User
from .models import OAuth2AuthorizationCode, OAuth2Token, OAuth2Client
from authlib.oidc.core.grants import OpenIDCode

from authlib.jose import JsonWebKey

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def save_authorization_code(self, code, request):
        code_challenge = request.data.get("code_challenge")
        code_challenge_method = request.data.get("code_challenge_method")
        nonce = request.data.get("nonce")
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.user_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce = nonce,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = User(username=username)
        if user is not None and user.check_password(password):
            return user


class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        if credential.user.valid:
            return credential.user
        else:
            self.revoke_old_credential(credential)
            return None

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


class MyOpenIDCode(OpenIDCode):

    def exists_nonce(self, nonce, request):
        exists = OAuth2AuthorizationCode.query.filter_by(
            client_id=request.payload.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self, grant):
        current_app.logger.debug("get_jwt_config called for client %s", grant.client.client_id)
        return {
            'key': current_app.config["PRIVATE_KEY_DATA"],
            'alg': 'RS256',
            'iss': "https://" + current_app.config["DOMAIN"],
            'exp': 3600
        }

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)
    
    def create_authorization_response(self, *args, **kwargs):
        current_app.logger.debug("OpenIDCode.create_authorization_response called")
        return super().create_authorization_response(*args, **kwargs)
    
    def check_response_type(self, response_type):
        current_app.logger.debug("OpenIDCode.check_response_type called with: %s", response_type)
        # force it to accept 'code' (or other response types you need)
        if response_type in ['code', 'id_token', 'code id_token']:
            return True
        return False

def query_client(client_id):
    return current_app.config["CLIENTS"][client_id]


save_token = create_save_token_func(db.session, OAuth2Token)
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
require_oauth = ResourceProtector()


def config_oauth(app):
    authorization.init_app(app)
    authorization.register_grant(AuthorizationCodeGrant, [MyOpenIDCode(require_nonce=False), CodeChallenge(required=True)])

    # support revocation
    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())


def generate_user_info(user, scope):
    return UserInfo(
        sub=str(user.user_id),
        name=user.extra_info.full_name,
        email=user.extra_info.email,
    )

def get_metadata():
    domain ="https://" +  current_app.config["DOMAIN"]
    return {
             "issuer": domain,
             "authorization_endpoint": f"{domain}/oauth/authorize",
                     "token_endpoint": f"{domain}/oauth/token",
        "userinfo_endpoint": f"{domain}/oauth/userinfo",
        "jwks_uri": f"{domain}/.well-known/jwks.json",
        "response_types_supported": ["code", "code id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid"],
        "claims_supported": ["sub", "name", "email"],
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "client_credentials", "password"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "code_challenge_methods_supported": ["S256"]
            }

def pubkey():
    keyset = JsonWebKey.import_key(current_app.config["PUBLIC_JWK"], kty="RSA").as_dict()
    return {"keys": [keyset]}
