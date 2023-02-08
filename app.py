import sqlite3

import bcrypt
from flask import Flask, session, redirect, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

from forms import LoginForm, RegisterForm

app = Flask(__name__)
app.secret_key = 'allo'
login_manager = LoginManager()
login_manager.init_app(app)
# without setting the login_view, attempting to access @login_required endpoints will result in an error
# this way, it will redirect to the login page
login_manager.login_view = 'login'
app.config['USE_SESSION_FOR_NEXT'] = True


class User(UserMixin):
    def __init__(self, username, email, phone, password=None):
        self.id = username
        self.email = email
        self.phone = phone
        self.password = password


# this is used by flask_login to get a user object for the current user
@login_manager.user_loader
def load_user(user_id):
    user = find_user(user_id)
    # user could be None
    if user:
        # if not None, hide the password by setting it to None
        user.password = None
    return user


def find_user(username):
    con = sqlite3.connect("data/users.sqlite")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT username, email, phone, password FROM users WHERE username = '{}';".format(username))
    user = cur.fetchone()
    con.close()
    if user:
        user = User(*user)
    return user


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = find_user(form.username.data)
        # user could be None
        # passwords are kept in hashed form, using the bcrypt algorithm
        if user and bcrypt.checkpw(form.password.data.encode(), user.password.encode()):
            login_user(user)
            flash('Logged in successfully.')

            # check if the next page is set in the session by the @login_required decorator
            # if not set, it will default to '/'
            next_page = session.get('next', '/')
            # reset the next page to default '/'
            session['next'] = '/'
            return redirect(next_page)
        else:
            flash('Incorrect username/password!')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()

    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        user = find_user(form.username.data)
        if not user:
            salt = bcrypt.gensalt()
            password = bcrypt.hashpw(form.password.data.encode(), salt)
            con = sqlite3.connect("data/users.sqlite")
            cur = con.cursor()
            cur.execute("INSERT INTO users(username, email, phone, password) VALUES('{}', '{}', '{}', '{}');".format(
                form.username.data, form.email.data, form.phone.data, password.decode()))
            con.commit()
            con.close()
            flash('Registered successfully.')
            return redirect('/login')
        else:
            flash('This username already exists, choose another one')
    return render_template('register.html', form=form)


@app.route('/')
def hello_world():
    return render_template('base.html')


@app.route('/info')
def info():
    headings = ('Name', 'Position', 'Email', 'Campus')
    data = [('Patrick Lebois', 'Director', 'patrick@amity.com', 'Laval'),
            ('Mary Tremblay', 'Vice Principal', 'marry@amity.com', 'Laval'),
            ('Kunal Patel', 'Maths Teacher', 'kunal@amity.com', 'Laval'),
            ('Bahar Erva', 'English Language Teacher', 'bahar@amity.com', 'Laval'),
            ('Yannick McAlly', 'Vice Principal', 'yannick@amity.com', 'Montreal'),
            ('Hassan Elkabir', 'Coordinator', 'hassan@amity.com', 'Montreal'),
            ('Helen Lechavette ', 'Vice Principal', 'helen@amity.com', 'Quebec City'),
            ('Simon Brown', 'Sport Teacher ', 'simon@amity.com', 'Quebec City'), ]

    return render_template('info.html', headings=headings, data=data)


@app.route('/careers')
@login_required
def careers():
    con = sqlite3.connect("data/users.sqlite")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM careers ")
    listCareers = cur.fetchall()

    con.close()

    return render_template('careers.html', listCareers=listCareers)


@app.route('/news')
@login_required
def news():
    con = sqlite3.connect("data/users.sqlite")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM news ")
    listNews = cur.fetchall()

    con.close()

    return render_template('news.html',
                           listnews=listNews)


if __name__ == '__main__':
    app.run()
