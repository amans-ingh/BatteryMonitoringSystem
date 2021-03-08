from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

application = Flask(__name__)
application.config['SECRET_KEY'] = '5791628bb0b13c53f4e0c676dfde4h280ba245'
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(application)
bcrypt = Bcrypt(application)

from bms import routes
