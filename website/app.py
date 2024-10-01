import os
import yaml

from flask import Flask
from .models import db, ExtraUserinfo, OAuth2Client
from .oauth2 import config_oauth
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


def read_userinfo(filename):
    with open(filename, "r") as f:
        user_confs = yaml.safe_load(f)

    extra_user_info = {}
    # convert to object to make sure we do some validation
    for username in user_confs:
        user = ExtraUserinfo(**user_confs[username])
        extra_user_info[username] = user
    return extra_user_info


def read_clients(filename):
    clients = {}
    with open(filename, "r") as f:
        client_confs = yaml.safe_load(f)
    for i in client_confs:
        client_id = client_confs[i]["client_id"]
        client = OAuth2Client(client_name=i, **client_confs[i])
        clients[client_id] = client
    return clients


def setup_app(app):
    settings_file = os.environ.get("OAUTH_SETTINGS", "settings.yml")
    with open(settings_file, "r") as f:
        settings = yaml.safe_load(f)

    app.config["CLIENTS"] = read_clients(settings["clients"])
    app.config["EXTRA_USER_INFO"] = read_userinfo(settings["users"])
    app.config["REALM"] = settings["realm"]

    db.init_app(app)
    # Create tables if they do not exist already
    with app.app_context():
        db.create_all()
    config_oauth(app)

    app.register_blueprint(bp, url_prefix="")
