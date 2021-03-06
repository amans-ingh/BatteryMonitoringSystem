from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_restful import Api
from secrets import token_hex
import os

application = Flask(__name__)
application.config['SECRET_KEY'] = token_hex(20)
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(application)
bcrypt = Bcrypt(application)
api = Api(application)

from bms import routes
from bms.myapi import MyApi

api.add_resource(MyApi, '/api/<string:token>/<string:task>')

if os.path.exists('bms/site.db'):
    pass
else:
    for f in os.listdir('csv'):
        os.remove(os.path.join('csv', f))
    db.create_all()
