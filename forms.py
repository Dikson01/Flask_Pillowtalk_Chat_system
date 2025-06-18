from flask_wtf import FlaskForm
from wtforms import StringField,IntegerField,SubmitField,EmailField,PasswordField
from wtforms.validators import DataRequired,Email,NumberRange,Length,EqualTo

class UserForm(FlaskForm):
    username = StringField("username",validators=[DataRequired(),Length(min=3)])
    email = EmailField("email",validators=[DataRequired(),Email()])
    password = PasswordField("password",validators=[DataRequired(),Length(min = 6)])
    confirm_password = PasswordField(
        "confirm password",
        validators=[DataRequired(),
                    EqualTo("password",message="password must match")]
    )
    submit = SubmitField("submit")
    

class LoginForm(FlaskForm):
    email = StringField("email",validators=[DataRequired(),Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")

class ForgotPasswordForm(FlaskForm):
    email = StringField("email",validators=[DataRequired(),Email()])
    submit = SubmitField("Send Reset Link")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("new password",validators=[DataRequired(),Length(min=6)])
    confirm_password = PasswordField(
        "confirm password",
        validators=[DataRequired(),
                    EqualTo("password",message="Password must match")])
    submit = SubmitField("Reset Password")