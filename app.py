from flask import Flask,render_template,url_for,redirect,flash
from forms import UserForm, LoginForm, ResetPasswordForm, ForgotPasswordForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_sqlalchemy import SQLAlchemy
from models import db, User
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,login_user,logout_user,login_required,current_user
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer,SignatureExpired,BadSignature

app = Flask(__name__)
app.secret_key='TopSecretkey'
csrf = CSRFProtect(app)
s = URLSafeTimedSerializer(app.secret_key)
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db.init_app(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "diksonsharma616@gmail.com"
app.config['MAIL_PASSWORD'] = "diko kzha cvkr wjov"
app.config['MAIL_DEFAULT_SENDER'] = "diksonsharma616@gmail.com"
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


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
        if User.query.first() is None:
            is_admin = True
        else:
            is_admin = False

        new_user=User(
            username = form.username.data,
            email = form.email.data,
            password = hashed_password,
        is_admin = is_admin)
        db.session.add(new_user)
        db.session.commit()

        msg = Message("Welcome To Dikson's app!",recipients=[new_user.email])
        msg.body = f'''Hi {new_user.username},
        Welcome to our Flask app! We are happy to have you onboard.
        Let us know if you ever need help.
        Chrees,
        Team Dikson'''
        mail.send(msg)

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
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout successfully","success")
    return redirect(url_for("index"))


@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('resetpassword', token=token, _external=True)

            # Send the email
            msg = Message("Password Reset Request",
                          recipients=[user.email])
            msg.body = f'''Hi {user.username},
            To reset your password, click the link below:
            {reset_url}
            If you didn’t request this, ignore this email.'''
            mail.send(msg)
            flash("A password reset link has been sent to your email.", "info")
            return redirect(url_for('login'))
        else:
            flash("No account found with that email.", "danger")
    return render_template("forgotpassword.html", form=form)


@app.route("/reset-password/<token>",methods=["GET","POST"])
def resetpassword(token):
    form = ResetPasswordForm()
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash("The reset link has expired. Please request a new one.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid or tampered link.", "danger")
        return redirect(url_for("forgot_password"))

    # Find the user with that email
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("No user found with that email.", "danger")
        return redirect(url_for("forgotpassword"))

    # If form submitted and valid, update the password
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been reset successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("resetpassword.html", form=form)


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:   # Check if the logged-in user is NOT an admin
        return "Access Denied. Admins only!", 403   # Block access with HTTP 403 Forbidden

    users = User.query.all()   # Fetch all users from the database
    return render_template('admin.html', users=users) 


@app.route("/deleteuser/<int:user_id>",methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "Access Denied. Admin only!",403
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash("You can't delete yourself!","danger")
        return redirect(url_for('admin'))
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f"User: {user_to_delete.username} is deleted successfully!", "success")
    return redirect(url_for("admin"))




if __name__ == '__main__':
    app.run(debug=True)