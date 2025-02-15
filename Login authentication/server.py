import os
import logging
import hmac
import hashlib

from dotenv import load_dotenv

from flask import (
    Flask, render_template, redirect, url_for, request, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
logging.getLogger('werkzeug').setLevel(logging.ERROR)


def compute_signature(username, password, secret_key):
    """
    Compute an HMAC SHA256 signature for data integrity checking.
    """
    message = f"{username}{password}".encode('utf-8')
    return hmac.new(
        secret_key.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )
    password = db.Column(
        db.String(150),
        nullable=False
    )
    data_signature = db.Column(
        db.String(64),
        nullable=False
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        existing_user = User.query.filter_by(
            username=username
        ).first()
        if existing_user:
            flash(
                'Username already exists. '
                'Please choose a different one.',
                'danger'
            )
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(
            request.form['password']
        ).decode('utf-8')
        signature = compute_signature(
            username,
            hashed_password,
            app.config['SECRET_KEY']
        )
        new_user = User(
            username=username,
            password=hashed_password,
            data_signature=signature
        )
        db.session.add(new_user)
        db.session.commit()
        flash(
            'Account created successfully! '
            'You can now log in.',
            'success'
        )
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(
            username=username
        ).first()
        if user:
            computed_sig = compute_signature(
                user.username,
                user.password,
                app.config['SECRET_KEY']
            )
            if computed_sig != user.data_signature:
                flash(
                    "Data integrity error. "
                    "Your account record appears to have been tampered with.",
                    "danger"
                )
                return redirect(url_for('login'))

            if bcrypt.check_password_hash(
                user.password,
                request.form['password']
            ):
                login_user(user)
                return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template(
        'dashboard.html',
        user=current_user
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("Server running on http://127.0.0.1:5000")
    app.run(debug=True)
