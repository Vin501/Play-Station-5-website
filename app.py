from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import url_for

# Flask app setup
app = Flask(__name__)
# use config SECRET_KEY and keep same value for serializer
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.secret_key = app.config['SECRET_KEY']

# Initialize serializer for password reset tokens (move here so it's available to routes)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Database setup (SQLite)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)



# Create database tables when the app starts (Flask 3.x compatible)
with app.app_context():
    db.create_all()

# Add a response header to prevent caching of pages (helps prevent showing protected pages from browser cache)
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ---------------- VALIDATORS ----------------
def is_valid_username(username: str) -> bool:
    """
    Username must:
    - contain only letters, numbers, and underscores
    - include at least one number and one underscore
    Example: user_1, vinay_23, test_9
    """
    return bool(re.match(r'^(?=.*\d)(?=.*_)[A-Za-z0-9_]+$', username))


# ---------------- ROUTES ----------------

#Home Route
@app.route('/')
def home():
    return render_template('home.html')


@app.context_processor
def inject_year():
    return {'current_year': datetime.now().year}


# Registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        address = request.form.get("address", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([name, mobile, address, email, username, password, confirm_password]):
            flash("Please fill all fields.", "error")
            return redirect(url_for("register"))
        
         # ✅ Username validation: letters, numbers, underscore, dot only
        if not re.match(r'^[A-Za-z0-9_.]+$', username):
            flash("Username can only contain letters, numbers, underscores, and dots.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return redirect(url_for("register"))

        if not re.match(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}', password):
            flash("Password must be at least 8 chars and include uppercase, lowercase, number and special char.", "error")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password)
        new_user = User(name=name, mobile=mobile, address=address, email=email, username=username, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, don't show login form
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please enter your email.', 'error')
            return redirect(url_for('forgot_password'))

        user = User.query.filter_by(email=email).first()
        if not user:
            # keep generic message for non-existent emails
            flash('If an account with that email exists, a reset link has been sent.', 'info')
            return redirect(url_for('login'))

        # create token (expires when validated)
        token = serializer.dumps(user.id, salt='password-reset-salt')
        # use relative reset URL for demo and redirect user immediately to the reset form
        reset_url = url_for('reset_password', token=token, _external=False)

        # Redirect user to reset page so they can set a new password immediately (demo)
        return redirect(reset_url)

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiry
    except SignatureExpired:
        flash('Reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid reset link.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.get(user_id)
    if not user:
        flash('Invalid reset link.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', token=token))

        if not re.match(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}', password):
            flash('Password must be at least 8 characters and include uppercase, lowercase, number and special character.', 'error')
            return redirect(url_for('reset_password', token=token))

        user.password = generate_password_hash(password)
        db.session.commit()
        flash('Your password has been updated. Please log in with the new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# Dashboard (Protected Page)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please login to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])


# Modify logout to fully clear session
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home', logged_out=1))


@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['user']).first()
    return render_template('profile.html', user=user)


@app.route('/games')
def games():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('games.html')



def is_valid_password(pw: str) -> bool:
    """Require min 8 chars, at least 1 upper, 1 lower, 1 digit and 1 special char."""
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$'
    return bool(re.match(pattern, pw))


@app.route('/static-check')
def static_check():
    root = os.path.join(os.path.dirname(__file__), 'static')
    if not os.path.isdir(root):
        return f"static folder not found: {root}"
    links = []
    for dirpath, dirnames, filenames in os.walk(root):
        for f in filenames:
            rel = os.path.relpath(os.path.join(dirpath, f), root).replace('\\','/')
            links.append(url_for('static', filename=rel))
    return '<br>'.join(f'<a href="{u}">{u}</a>' for u in sorted(links))

# Run the app
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)
