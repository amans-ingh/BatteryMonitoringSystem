from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

application = Flask(__name__)
application.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
application.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bms.db'
db = SQLAlchemy(application)
bcrypt = Bcrypt(application)

from bms import routes