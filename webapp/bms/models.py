from bms import db
from secrets import token_hex


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    batteries = db.relationship('Battery', backref='owner', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Battery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    token = db.Column(db.String(30), unique=True, nullable=False, default=token_hex(30))
    last_health = db.Column(db.Float, nullable=True)
    last_temp = db.Column(db.Float, nullable=False, default=30)
    last_soc = db.Column(db.Float, nullable=True)
    last_voltage = db.Column(db.Float, nullable=True)
    last_time = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.name}', '{self.token}')"