from flask import render_template, url_for, flash, redirect, request, make_response, Response
from bms import application, bcrypt, db
import json, time, random
from datetime import datetime
from bms.models import User, Battery
random.seed()  # Initialize the random number generator

@application.route('/', methods=['GET', 'POST'])
def index():
    username = request.cookies.get('username')
    if username:
        return render_template('main.html', username=username)
    return render_template('main.html')


@application.route('/login', methods=['GET', 'POST'])
def login():
    username = request.cookies.get('username')
    next_url = request.form.get("next")
    if username:
        return redirect('/')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user=User.query.filter_by(username=username).first()
        if user:
            pwd=bcrypt.check_password_hash(user.password, password)
            if pwd:
                if next_url:
                    resp = make_response(redirect(next_url))
                    resp.set_cookie('username', username)
                    return resp
                resp = make_response(redirect('/'))
                resp.set_cookie('username', username)
                return resp
            else:
                flash("Incorrect username or password", "danger")
                return render_template('login.html')
        else:
            flash("Incorrect username or password", "danger")
            return render_template('login.html')
    return render_template('login.html')


@application.route('/register', methods=['GET', 'POST'])
def register():
    username = request.cookies.get('username')
    if username:
        return redirect('/')
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user:
            flash("Username already taken!")
            return redirect(url_for('register'))
        hashed_pw = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        user = User(name=request.form.get('name'), username=request.form.get('username'), password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully", "success")
        return redirect(url_for('login'))
    return render_template('register.html')


@application.route('/home', methods=['GET', 'POST'])
def home():
    username = request.cookies.get('username')
    if username:
        return render_template('home.html', username=username)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/temperature', methods=['GET', 'POST'])
def temperature():
    username = request.cookies.get('username')
    if username:
        return render_template('temp.html', username=username)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/voltage', methods=['GET', 'POST'])
def voltage():
    username = request.cookies.get('username')
    if username:
        return render_template('voltage.html', username=username)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/soc', methods=['GET', 'POST'])
def soc():
    username = request.cookies.get('username')
    if username:
        return render_template('soc.html', username=username)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/soh', methods=['GET', 'POST'])
def soh():
    username = request.cookies.get('username')
    if username:
        return render_template('soh.html', username=username)
    return redirect(url_for('login', next=request.endpoint))


@application.route('/chart-data', methods=['GET', 'POST'])
def chart_data():
    def generate_random_data():
        while True:
            json_data = json.dumps(
                {'time': datetime.now().strftime('%M:%S'), 'temp': random.randint(290, 310)/10, 'voltage': random.randint(25, 35)/10, 'soc': random.randint(90, 100), 'soh': random.randint(90, 100)})
            yield f"data:{json_data}\n\n"
            time.sleep(1)

    return Response(generate_random_data(), mimetype='text/event-stream')


@application.route('/user', methods=['GET', 'POST'])
def user():
    username = request.cookies.get('username')
    if username:
        return render_template('user.html', username=username)
    return redirect(url_for('login', next=request.endpoint))

@application.route('/logout', methods=['GET'])
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('username')
    return resp
