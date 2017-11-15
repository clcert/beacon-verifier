from flask import Flask


application = Flask(__name__, static_url_path='/verifier/static')

from app import public
