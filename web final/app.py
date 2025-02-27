import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this in production!

# Configure database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # 'found' or 'lost'

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Access denied. Please log in as admin.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template('index.html', username=session.get("username"))

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    hashed_password = generate_password_hash(password)

    new_user = User(username=username, email=email, password=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
    except:
        flash("Username or Email already exists.", "error")
    
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['username'] = user.username  # Store username in session
        session['email'] = user.email  # Store email in session
        flash(f"Login successful! Welcome, {username}.", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid username or password. Please try again.", "error")
    
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("main.html")

@app.route('/profile')
@login_required
def profile():
    username = session.get("username")
    email = session.get("email")
    return render_template("profile.html", username=username, email=email)

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash("Logged out successfully!", "success")
    return redirect(url_for('home'))

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route('/report')
@login_required
def report():
    return render_template('report.html')

@app.route('/add', methods=['POST'])
@login_required
def add_item():
    item_name = request.form['item_name']
    location = request.form['location']
    date = request.form['date']
    category = request.form['category']
    description = request.form['description']
    status = 'found'  # Default status is 'found'

    # Ensure the upload folder exists
    upload_folder = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    # Handle file upload
    image = request.files['image']
    if image and image.filename != '':
        filename = secure_filename(image.filename)
        filepath = os.path.join(upload_folder, filename)
        image.save(filepath)
    else:
        filename = None  # No image uploaded

    # Save to database
    new_item = Item(
        item_name=item_name,
        location=location,
        date=date,
        category=category,
        description=description,
        image=filename,
        status=status
    )
    db.session.add(new_item)
    db.session.commit()

    flash("Item successfully added!", "success")
    return redirect(url_for('found'))

@app.route('/found')
@login_required
def found():
    found_items = Item.query.filter_by(status='found').all()
    return render_template('found.html', found=found_items)

# Admin routes
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hardcoded admin credentials
        admin_username = 'admin'
        admin_password = 'admin123'

        if username == admin_username and password == admin_password:
            session['is_admin'] = True  # Set session for admin
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials. Please try again.', 'error')

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    items = Item.query.all()
    return render_template('admin_dashboard.html', users=users, items=items)

@app.route('/admin_logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Admin logged out successfully!', 'success')
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
