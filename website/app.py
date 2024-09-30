import os
import yaml

from flask import Flask
from .models import db, read_userinfo, set_realm
from .oauth2 import config_oauth, read_clients
from .routes import bp


def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object("website.settings")

    # load environment configuration
    if "WEBSITE_CONF" in os.environ:
        app.config.from_envvar("WEBSITE_CONF")

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith(".py"):
            app.config.from_pyfile(config)

    setup_app(app)
    return app


def setup_app(app):

    db.init_app(app)
    # Create tables if they do not exist already
    with app.app_context():
        db.create_all()
    config_oauth(app)

    settings_file = os.environ.get("OAUTH_SETTINGS", "settings.yml")
    with open(settings_file, "r") as f:
        settings = yaml.safe_load(f)

    set_realm(settings["realm"])
    read_clients(settings["clients"])
    read_userinfo(settings["users"])

    app.register_blueprint(bp, url_prefix="")
