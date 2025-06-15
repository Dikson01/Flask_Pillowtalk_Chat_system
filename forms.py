from flask_wtf import FlaskForm
from wtforms import StringField,IntegerField,SubmitField,EmailField,PasswordField
from wtforms.validators import DataRequired,Email,NumberRange,Length

class UserForm(FlaskForm):
    username = StringField("username",validators=[DataRequired(),Length(min=3)])
    email = EmailField("email",validators=[DataRequired(),Email()])
    password = PasswordField("password",validators=[DataRequired(),Length(min = 6)])
    submit = SubmitField("submit")
    