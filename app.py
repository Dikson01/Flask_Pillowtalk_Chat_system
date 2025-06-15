from flask import Flask,render_template,request,url_for,redirect,flash
from forms import UserForm
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.secret_key='TopSecretkey'
csrf = CSRFProtect(app)

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

        print(f"Username : {username}, Email : {email}, Password : {password}")
        flash(f"User {username} Successfully registered!")

        return redirect(url_for("register"))
    
    return render_template("form.html", form=form)


if __name__ == '__main__':
    app.run(debug=True)