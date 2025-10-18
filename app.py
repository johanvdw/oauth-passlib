from website.app import create_app
import logging

logging.getLogger("authlib").setLevel(logging.DEBUG)

app = create_app(
    {
        "SECRET_KEY": "secret",
        "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///db.sqlite",
    }
)
