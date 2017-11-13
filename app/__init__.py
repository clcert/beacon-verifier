from flask import Flask


application = Flask(__name__)
application.config["APPLICATION_ROOT"] = "/verifier"

from app import public
