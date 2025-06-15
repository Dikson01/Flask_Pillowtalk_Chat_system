from flask import Flask,render_template,request,url_for,redirect,flash
from forms import UserForm
from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from models import db, User

app = Flask(__name__)
app.secret_key='TopSecretkey'
csrf = CSRFProtect(app)

app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db.init_app(app)

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
        new_user=User(
            username = form.username.data,
            email = form.email.data,
            password = form.password.data)
        db.session.add(new_user)
        db.session.commit()

        flash(f"User Successfully registered!")

        return redirect(url_for("register"))
    
    return render_template("form.html", form=form)


if __name__ == '__main__':
    app.run(debug=True)