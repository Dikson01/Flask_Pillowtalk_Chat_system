from flask import Flask,render_template,request,url_for,redirect,flash
from forms import UserForm, LoginForm
from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from models import db, User
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,login_user,logout_user,login_required,current_user


app = Flask(__name__)
app.secret_key='TopSecretkey'
csrf = CSRFProtect(app)

app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# @app.route('/')
# def home():
#     return 'yo bro this is my flask page 1'

@app.route('/')
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter(
            (User.username == username)|(User.email == email)
        ).first()

        if existing_user:
            flash("username or email already exist try another.",'danger')
            return render_template("form.html",form=form)

        hashed_password = generate_password_hash(form.password.data)
        new_user=User(
            username = form.username.data,
            email = form.email.data,
            password = hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')

        return redirect(url_for("register"))
    else:
        print(form.errors)
    
    return render_template("form.html", form=form)

@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter(User.email == form.email.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successfully!","success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password!","danger")

    return render_template("login.html", form = form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/dashboard")
@login_required
def dashboard():
    return f"Hello, {current_user.username}"
        


if __name__ == '__main__':
    app.run(debug=True)