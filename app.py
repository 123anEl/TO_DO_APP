from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import flask_MailboxValidator
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_login import current_user, login_user, UserMixin, LoginManager, logout_user, login_required

app = Flask(__name__)

login_manager = LoginManager(app)
login_manager.init_app(app)
app.secret_key = 'todoapp'
app.config['DEBUG'] = False
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config.from_pyfile('config.cfg')
mail = Mail(app)
s = URLSafeTimedSerializer('Thisisasecret!')

#Connecting to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['todo_app']
collection = db['todos']
users = db['users']

class User(UserMixin):
    def __init__(self, _id, username, email, password=None, photo=None):
        self.id = _id
        self.username = username
        self.email = email
        self.psw = password
        self.photo = photo or None

    @staticmethod
    def get(id):
        user = users.find_one({"_id": ObjectId(id)})
        if not user:
            return None
        photo = user.get('photo')
        return User(str(user['_id']), user['username'], user['email'], user['psw'], photo)

    def set_password(self, new_password):
        self.psw = generate_password_hash(new_password)

    @staticmethod
    def check_password(user, password):
        return check_password_hash(user.psw, password)

    @property
    def photo_url(self):
        if self.photo:
            return self.photo
        return url_for('static', filename='img/default-profile-pic.jpg')


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

        # Retrieve all documents from the 'todos' collection
    todos = db.todos.find({"user_id": current_user.id})

    return render_template('index.html', todos=todos, user=current_user)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/add', methods=['POST'])
@login_required
def add_todo():
    # Get the todo from the form input
    todo_title = request.form.get('title')
    # Create a new todo
    new_todo = {"title": todo_title, "complete": False, "user_id": current_user.id}
    # Insert the todo into the database
    collection.insert_one(new_todo)
    # Redirect back to the homepage
    return redirect(url_for('index'))

@app.route('/update/<id>')
@login_required
def update_todo(id):
    # Find the todo by its id
    todo = collection.find_one({"_id": ObjectId(id)})
    # Update the todo's "complete" field to True
    collection.update_one({"_id": ObjectId(id)}, {"$set": {"complete": True}})
    # Redirect back to the homepage
    return redirect(url_for('index'))

@app.route('/delete/<id>')
@login_required
def delete_todo(id):
    # Delete the todo by its id
    collection.delete_one({"_id": ObjectId(id)})
    # Redirect back to the homepage
    return redirect(url_for('index'))

@app.route('/edit')
@login_required
def edit():
    return render_template("edit.html", user=current_user)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/edit', methods=['POST'])
@login_required
def edit_profile():
    user_id = current_user.id
    if request.method == 'POST':
        # Get the data from the form
        new_username = request.form['newusername']
        new_email = request.form['newemail']
        new_password = request.form['newpassword']

        # Update the user's data in the database
        photo_file = request.files.get('newphoto')
        if photo_file and allowed_file(photo_file.filename):
            filename = secure_filename(photo_file.filename)
            photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            photo_url = url_for('uploaded_file', filename=filename, _external=True)
            users.update_one(
                {"_id": ObjectId(user_id)},
                {'$set': {'username': new_username, 'email': new_email, 'psw': new_password, 'photo': photo_url}}
            )
        else:
            users.update_one(
                {"_id": ObjectId(user_id)},
                {'$set': {'username': new_username, 'email': new_email, 'psw': new_password}}
            )
        user = users.find_one({"_id": ObjectId(user_id)})
        # Render the edit profile template
        return render_template('profile.html', user=user)

    return render_template('edit.html', user=current_user)

@app.route('/home')
def home():
    return render_template("home.html")

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def checklogin():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    username_l = request.form.get("username_l")
    psw_l = request.form.get("psw_l")
    correct_user = db.users.find_one({"username": username_l, "psw": psw_l})
    if correct_user:
        # Create a User object with the required arguments
        user = User(str(correct_user["_id"]), correct_user['username'], correct_user['email'], correct_user['psw'])
        login_user(user)
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

@app.route('/register')
def register():
    return render_template("register.html")



mbv = flask_MailboxValidator.SingleValidation('T058WMK58YCGMMVSLNFN')

@app.route('/register',  methods=['POST'])
def adduser():
    email = request.form.get("email")
    username = request.form.get("username")
    psw = request.form.get("psw")
    psw2 = request.form.get("psw2")
    hashed_psw = generate_password_hash(psw)
    user = {"email": email, "username": username, "password": hashed_psw, "psw": psw}
    user_exist = db.users.find_one({"username": username})

    token = s.dumps(email, salt='email-confirm')
    msg = Message('Confirm email', sender='onlan.anel2003@gmail.com', recipients=[email])
    link = url_for('confirm_email', token=token, _external=True)
    msg.body = 'Your link is {}'.format(link)

    if user_exist:
        raise ValidationError("The username already exists.")
    else:
        if len(psw) > 7 and len(psw) < 20:
            if psw == psw2:
                result = users.insert_one(user)
                if result:
                    mail.send(msg)
                    return ("<h1>Check your mailbox</h1>")
            else:
                return '<h1>Repeat password correctly</h1>'
        else:
            return '<h1>Password must be at least 7 characters in length.</h1>'


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email2 = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == 'main':
    app.run(debug=True)

