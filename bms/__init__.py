from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

application = Flask(__name__)
application.config['SECRET_KEY'] = '5791628bb2340b13c8a6dfa3sd567280ba245'
application.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(application)
bcrypt = Bcrypt(application)

from bms import routes
