# Source/app.py
from flask import Flask, render_template, flash, redirect, url_for, request
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, SubmitField
from wtforms.fields import TextAreaField
from flask_wtf.file import FileField, FileAllowed
from wtforms import SelectField
from wtforms.validators import DataRequired, EqualTo, Length
from werkzeug.utils import secure_filename
from PIL import Image
import sqlite3
import os

DATABASE = "greetings_earthlings.db"
login_manager = LoginManager()
bcrypt = Bcrypt()
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'f9a1d7aa68dcbeb63915b71341d9038967e5e25cb969591d'
csrf = CSRFProtect(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 12 * 1024 * 1024  # limit upload size 

login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        user_data = cur.execute(
            '''
            SELECT id, username, email, password FROM user
            WHERE id = ? LIMIT 1
            ''',
            (user_id,),
        ).fetchone()
        conn.close()

        if user_data:
            return User(id=user_data[0], username=user_data[1], email=user_data[2], password=user_data[3])
        else:
            return None


class PostForm(FlaskForm):
    postText = TextAreaField('Post Text', validators=[DataRequired()])
    category = SelectField('Category', choices=[('Projects', 'Projects'), ('Travel', 'Travel')])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Submit')

class Post:
    @staticmethod
    def create_post():
        post_text = request.form.get('postText')
        category = request.form.get('category')
        image = request.files['image']
        user_id = current_user.id if current_user.is_authenticated else None
       
        try:
            conn = sqlite3.connect(DATABASE)
            cur = conn.cursor()

            # Save the image and get its path
            if image:
                filename = secure_filename(image.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)
                
                # Get the image size
                with Image.open(image_path) as img:
                    image_size = f"{img.width}x{img.height}"
            else:
                image_path = None
                image_size = None

            # Check if category is not None
            if category is not None:
                # Insert the post with category, image path, and image size
                cur.execute("INSERT INTO posts (post_text, category, image_path, image_size, user_id) VALUES (?, ?, ?, ?, ?)",
                    (post_text, category, image_path, image_size, user_id))
            else:
                # Insert the post without category, but with image path and image size
                cur.execute("INSERT INTO posts (post_text, category, image_path, image_size, user_id) VALUES (?, ?, ?, ?, ?)",
                    (post_text, category, image_path, image_size, user_id))
                
            conn.commit()
            db_msg = "Post successfully added to the database"
        except Exception as e:
            conn.rollback()
            db_msg = f"Error in insert operation: {e}"
        finally:
            print(db_msg)
            conn.close()


class Post:
    @staticmethod
    def get_latest_posts(limit=5):
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        posts = cur.execute(
            '''
            SELECT p.id, p.post_text, u.username
            FROM posts p
            JOIN user u ON p.user_id = u.id
            ORDER BY p.id DESC
            LIMIT ?
            ''',
            (limit,)
        ).fetchall()
        conn.close()

        return posts


class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email Address', [validators.Email()])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password', [validators.DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=5, message='Password must be at least 5 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
@app.route('/home')
def home():
    form = PostForm()
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        # Fetch posts along with the author's username
        cur.execute("""
            SELECT p.id, p.post_text, p.image_path, p.image_size, u.username 
            FROM posts p
            LEFT JOIN user u ON p.user_id = u.id
            ORDER BY p.id DESC LIMIT 5
        """)
        latest_posts = cur.fetchall()
        conn.commit()
        db_msg = "Latest posts successfully obtained"
    except Exception as e:
        conn.rollback()
        db_msg = f"Error fetching latest posts: {e}"
        latest_posts = []
    finally:
        print(db_msg)
        conn.close()

    return render_template('front_1.html', latest_posts=latest_posts, form=form)

'''
# Route template provided by the professor CMT120
@app.route("/list_greeted", methods=["GET", "POST"])
def database_interface():
    # call all items from database here
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT * FROM names")
        db_data = cur.fetchall()
        # print(db_data, type(db_data))
        # a list of tuples is returned, each tuple in the list has 3 items (0,1,2)
        # tuple[0] is ID, tuple[1] first_name, tuple[2] surname.
        # Remember this for referring to variables in HTML Jinja templating
        conn.commit()
        db_msg = "data successfully obtained"
    except:
        conn.rollback()
        db_msg = "error fetching table data"
    finally:
        print(db_msg)
        conn.close()

    return render_template("greeted.html", title="hellod to", db_data=db_data)
'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        try:
            conn = sqlite3.connect(DATABASE)
            cur = conn.cursor()

            # Check if username already exists
            cur.execute('''
                SELECT * FROM user WHERE username = ?
            ''', (form.username.data,))
            if cur.fetchone():
                flash('Username already exists. Please choose a different one.', 'error')
                return render_template('register.html', form=form)

            # Hash the password before storing it
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            # Continue with user registration
            cur.execute('''
                INSERT INTO user (username, email, password)
                VALUES (?, ?, ?)
            ''', (form.username.data, form.email.data, hashed_password))
            conn.commit()
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            conn.rollback()
            flash(f'Registration failed. Error: {e}', 'error')

        finally:
            conn.close()

    return render_template('register.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        try:
            conn = sqlite3.connect(DATABASE)
            cur = conn.cursor()

            entered_username = form.username.data
            print("Entered Username:", entered_username)

            user_data = cur.execute(
                '''
                SELECT id, username, email, password FROM user
                WHERE LOWER(username) = LOWER(?) LIMIT 1
                ''',
                (entered_username,),
            ).fetchone()

            print("User Data:", user_data)

            if user_data:
                hashed_password_from_db = user_data[3]
                print("Hashed Password from DB:", hashed_password_from_db)

                if bcrypt.check_password_hash(hashed_password_from_db, form.password.data.encode('utf-8')):
                    user = User(id=user_data[0], username=user_data[1], email=user_data[2], password=user_data[3])
                    login_user(user)
                    print("Current User:", current_user)
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password. Please try again.', 'danger')
            else:
                flash('User not found. Please check your username.', 'danger')

        except sqlite3.Error as e:
            flash(f'Login failed. Database connection error: {e}', 'error')
            print(f'Database connection error: {e}')

        finally:
            conn.close()

    # Default return to render the login template
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    print("Current User: ", current_user)
    print("Authenticated: ", current_user.is_authenticated)
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        try:
            conn = sqlite3.connect(DATABASE)
            cur = conn.cursor()

            # Fetch the current user's hashed password from the database
            cur.execute('''
                SELECT password FROM user WHERE id = ?
            ''', (current_user.id,))
            user_data = cur.fetchone()

            if user_data and bcrypt.check_password_hash(user_data[0], form.current_password.data):
                # Hash the new password
                hashed_new_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')

                # Update the user's password in the database
                cur.execute('''
                    UPDATE user SET password = ? WHERE id = ?
                ''', (hashed_new_password, current_user.id))
                conn.commit()

                flash('Password changed successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Current password is incorrect.', 'error')

        except Exception as e:
            conn.rollback()
            flash(f'Error changing password: {e}', 'error')

        finally:
            conn.close()

    return render_template('change_password.html', form=form)


@app.route('/delete_account')
@login_required
def delete_account():
    try:
        user_id = current_user.id
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()

        # First, delete the user's posts from the database
        cur.execute("DELETE FROM posts WHERE user_id = ?", (user_id,))
        
        # Then, delete the user's account
        cur.execute("DELETE FROM user WHERE id = ?", (user_id,))
        conn.commit()

        # Flash a success message
        flash('Account and associated posts deleted successfully!', 'success')

        # Logout the user after account deletion
        logout_user()

    except Exception as e:
        # In case of an error, rollback the transaction
        conn.rollback()
        flash(f'Error deleting account and posts: {e}', 'error')

    finally:
        # Always close the database connection
        conn.close()

    # Redirect to the home page or login page after account deletion
    return redirect(url_for('home'))



@app.route('/post', methods=['GET', 'POST'])
def handle_post():
    form = PostForm()

    if form.validate_on_submit():
        post_text = form.postText.data
        category = form.category.data
        image = form.image.data
        user_id = current_user.id if current_user.is_authenticated else None

        image_path = None
        image_size = None

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_rel_path = os.path.join('uploads', filename).replace('\\', '/')  # Replacing backslashes
            full_image_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
            
            # Ensure the upload folder exists
            os.makedirs(os.path.dirname(full_image_path), exist_ok=True)

            try:
                image.save(full_image_path)
                print(f"Debug: Image saved at {full_image_path}")

                with Image.open(full_image_path) as img:
                    image_size = f"{img.width}x{img.height}"
                print(f"Debug: Image size - {image_size}")

                image_path = image_rel_path  # Use the relative path for the database
            except Exception as e:
                flash(f'Error handling image: {e}', 'error')
                return redirect(url_for("home"))

        try:
            with sqlite3.connect(DATABASE) as conn:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO posts (post_text, category, image_path, image_size, user_id) VALUES (?, ?, ?, ?, ?)", 
                    (post_text, category, image_path, image_size, user_id)
                )
                conn.commit()
                print("Debug: Post inserted into database")
            flash('Published!', 'success')
        except Exception as e:
            flash(f'Error in insert operation: {e}', 'error')
            print(f"Debug: Error in insert operation - {e}")
            return redirect(url_for("home"))

        return redirect(url_for("home"))

    return render_template('front_1.html', project_posts=project_posts, form=form)



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/your-form-route', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/projects', methods=['GET'])
def projects():
    filter_size = request.args.get('filter-size', '')
    filter_order = request.args.get('filter-order', 'recent')

    # Query the database to get "Projects" posts made by users along with user details
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    # Build the SQL query based on filters
    sql_query = "SELECT p.id, p.post_text, p.image_path, p.image_size, p.user_id, u.username FROM posts p JOIN user u ON p.user_id = u.id WHERE p.category = 'Projects'"

    if filter_size:
        sql_query += f" AND p.image_size = '{filter_size}'"

    # Add order condition to the query
    if filter_order == 'recent':
        sql_query += " ORDER BY p.id DESC"
    elif filter_order == 'oldest':
        sql_query += " ORDER BY p.id ASC"
    elif filter_order == 'size-asc':
        sql_query += " ORDER BY p.image_size ASC"
    elif filter_order == 'size-desc':
        sql_query += " ORDER BY p.image_size DESC"

    project_posts = cur.execute(sql_query).fetchall()
    conn.close()

    # Create an instance of FlaskForm
    form = FlaskForm()

    return render_template('projects.html', project_posts=project_posts, form=form)

from flask_wtf import FlaskForm
from flask import render_template, request
import sqlite3


@app.route('/explore', methods=['GET'])
def explore():
    filter_order = request.args.get('filter-order', 'recent')

    # Open a connection to the database
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    # Build the SQL query based on the filter_order
    sql_query = "SELECT p.id, p.post_text, p.image_path, p.image_size, p.user_id, u.username FROM posts p LEFT JOIN user u ON p.user_id = u.id"

    # Add order condition to the query
    if filter_order == 'recent':
        sql_query += " ORDER BY p.id DESC"
    elif filter_order == 'oldest':
        sql_query += " ORDER BY p.id ASC"
    elif filter_order == 'size-asc':
        sql_query += " ORDER BY p.image_size ASC"
    elif filter_order == 'size-desc':
        sql_query += " ORDER BY p.image_size DESC"

    # Execute the query and fetch the results
    all_posts = cur.execute(sql_query).fetchall()

    # Close the database connection
    conn.close()

    # Create an instance of FlaskForm (for CSRF protection)
    form = FlaskForm()

    # Render the explore template with the fetched posts and the form
    return render_template('explore.html', all_posts=all_posts, form=form)


@app.route('/travels', methods=['GET'])
def travels():
    filter_size = request.args.get('filter-size', '')
    filter_order = request.args.get('filter-order', 'recent')

    # Open a connection to the database
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    # Build the SQL query based on filters
    sql_query = "SELECT p.id, p.post_text, p.image_path, p.image_size, p.user_id, u.username FROM posts p JOIN user u ON p.user_id = u.id WHERE p.category = 'Travel'"

    # Apply filters if any are set
    if filter_size:
        sql_query += f" AND p.image_size = '{filter_size}'"

    # Add order condition to the query
    if filter_order == 'recent':
        sql_query += " ORDER BY p.id DESC"
    elif filter_order == 'oldest':
        sql_query += " ORDER BY p.id ASC"
    elif filter_order == 'size-asc':
        sql_query += " ORDER BY p.image_size ASC"
    elif filter_order == 'size-desc':
        sql_query += " ORDER BY p.image_size DESC"

    # Execute the query and fetch the results
    travel_posts = cur.execute(sql_query).fetchall()

    # Close the database connection
    conn.close()

    # Create an instance of FlaskForm 
    form = FlaskForm()

    # Render the travels template with the fetched posts
    return render_template('travels.html', travel_posts=travel_posts, form=form)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
        post_user_id = cur.fetchone()

        # Allow deletion if the post is by the current user or if it's a guest post
        if post_user_id and (post_user_id[0] == current_user.id or post_user_id[0] is None):
            cur.execute("DELETE FROM posts WHERE id = ?", (post_id,))
            conn.commit()
            flash("Post deleted successfully.", "success")
        else:
            flash("You are not authorized to delete this post.", "error")

    except Exception as e:
        flash(f"An error occurred: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('explore'))  # Redirect back to the explore page




def create_table():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    # Create posts table with new columns if it doesn't exist
    cur.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_text TEXT,
            category TEXT,
            image_path TEXT,
            image_size TEXT,
            user_id INTEGER REFERENCES user(id)
        )
    ''')

    # Create user table if it doesn't exist
    cur.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
