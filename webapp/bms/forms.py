from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from bms.models import User


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[Length(min=2, max=30)])
    username = StringField('Username', validators=[Length(min=2, max=20)])
    email = StringField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Use Login Instead')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    name = StringField('Name', validators=[Length(min=2, max=30)])
    username = StringField('Username', validators=[Length(min=2, max=20)])
    email = StringField('Email', validators=[Email()])
    prev_username = StringField('username_prev')
    prev_email = StringField('email_prev')
    submit = SubmitField('Update')


class AddBattery(FlaskForm):
    name = StringField('Name', validators=[Length(min=2, max=20)])
    capacity = SelectField('Capacity', default='1.1', choices=[('1.1', '1.1 Ampere Hour')])
    voltage = SelectField('Voltage', default='3.3', choices=[('3.3', '3.3 Volts')])
    submit = SubmitField('Add')


class ChangePassword(FlaskForm):
    username = StringField('Username', validators=[Length(min=2, max=20)])
    password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('new_password')])
    submit = SubmitField('Change')


class MessageBattery(FlaskForm):
    message = StringField('Note', validators=[Length(min=2)])
    submit = SubmitField('Update')
