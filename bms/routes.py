from flask import render_template, url_for, flash, redirect, request, make_response, Response
from bms import application, bcrypt, db
import json, time, random
from datetime import datetime
from bms.models import User, Battery
from bms.forms import RegistrationForm, LoginForm, UpdateAccountForm, AddBattery, ChangePassword


@application.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('index'))


@application.route('/')
def index():
    username = request.cookies.get('email')
    if username:
        return render_template('index.html', username=username)
    return render_template('index.html')


@application.route('/login', methods=['GET', 'POST'])
def login():
    username = request.cookies.get('email')
    next_url = request.form.get("next")
    if username:
        return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if next_url:
                resp = make_response(redirect(url_for(next_url)))
                resp.set_cookie('email', form.email.data)
                return resp
            resp = make_response(redirect('/'))
            resp.set_cookie('email', form.email.data)
            return resp
        else:
            flash("Incorrect username or password", "danger")
    return render_template('login.html', title='Login', form=form)


@application.route('/register', methods=['GET', 'POST'])
def register():
    username = request.cookies.get('email')
    if username:
        return redirect('/')
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully", "success")
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@application.route('/add', methods=['GET', 'POST'])
def add():
    username = request.cookies.get('email')
    if username:
        form = AddBattery()
        if form.validate_on_submit():
            user = User.query.filter_by(email=username).first()
            battery = Battery(name=form.name.data, user_id=user.id)
            db.session.add(battery)
            db.session.commit()
            flash('Battery Added!', 'success')
            return redirect(url_for('home'))
        return render_template('add.html', username=username, form=form)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/home', methods=['GET'])
def home():
    username = request.cookies.get('email')
    if username:
        user = User.query.filter_by(email=username).first()
        batts = Battery.query.filter_by(user_id=user.id).all()
        return render_template('home.html', username=username, batts=batts)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/account', methods=['GET', 'POST'])
def account():
    username = request.cookies.get('email')
    if username:
        user = User.query.filter_by(email=username).first()
        form = UpdateAccountForm()
        if form.validate_on_submit():
            user.email = form.email.data
            user.name = form.name.data
            user.username = form.username.data
            db.session.commit()
            flash("Account Information Updated Successfully!", "success")
            resp = make_response(redirect('/account'))
            resp.set_cookie('email', form.email.data)
            return resp
            # return redirect(url_for('account'))
        elif request.method == 'GET':
            form.email.data = user.email
            form.name.data = user.name
            form.username.data = user.username
        return render_template('user.html', username=username, form=form, user=user)
    return redirect(url_for('login', next=request.endpoint))

@application.route('/changepassword', methods=['GET', 'POST'])
def changepassword():
    username = request.cookies.get('email')
    if username:
        user = User.query.filter_by(email=username).first()
        form = ChangePassword()
        if form.validate_on_submit():
            if bcrypt.check_password_hash(user.password, form.password.data):
                user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                db.session.commit()
                flash('Password changed successfully', 'success')
                return redirect(url_for('account'))
            else:
                flash('Incorrect password!, Please try again.', 'danger')
                return redirect('changepassword')
        elif request.method == 'GET':
            form.username = user.username
        return render_template('changepassword.html', form=form, username=username, user=user)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('email')
    return resp


@application.route('/chart-data', methods=['GET', 'POST'])
def chart_data():
    def generate_random_data():
        while True:
            json_data = json.dumps(
                {'time': datetime.now().strftime('%M:%S'),
                 'temp': random.randint(290, 310) / 10,
                 'voltage': random.randint(25, 35) / 10,
                 'soc': random.randint(90, 100),
                 'soh': random.randint(90, 100)
                 }
            )
            yield f"data:{json_data}\n\n"
            time.sleep(1)
    return Response(generate_random_data(), mimetype='text/event-stream')











