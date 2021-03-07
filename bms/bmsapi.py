from flask import Flask
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from secrets import token_hex


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
api = Api(app)

class Battery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(30), unique=True, nullable=False, default=token_hex(30))
    last_health = db.Column(db.Float, nullable=True)
    last_temp = db.Column(db.Float, nullable=False, default=30)
    last_soc = db.Column(db.Float, nullable=True)
    last_voltage = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.name}', '{self.token}')"



class bmsapi(Resource):
    def get(self, token):
        battery = Battery.query.filter_by(token=token).first()
        if battery:
            json_battery = {'id': str(battery.id),
                            'name': str(battery.name),
                            'token': str(battery.token),
                            'last_health': str(battery.last_health),
                            'last_soc': str(battery.last_soc),
                            'last_voltage': str(battery.last_voltage)
                            }
            return json_battery
        return {'message': 'Invalid token'}, 401

    def put(self, token):
        battery = Battery.query.filter_by(token=token).first()
        if battery:
            True
            return {'message': 'It worked'}, 201
        return {'message': 'Invalid token'}, 401

    def delete(self, token):
        battery = Battery.query.filter_by(token=token).first()
        if battery:
            True
            return '', 204
        return {'message': 'Invalid token'}, 401


api.add_resource(bmsapi, '/api/<string:token>')

app.run(debug=True, port=int("80"))
