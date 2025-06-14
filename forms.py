from flask_wtf import FlaskForm
from wtforms import StringField,IntegerField,SubmitField,EmailField
from wtforms.validators import DataRequired,Email,NumberRange

class UserForm(FlaskForm):
    name = StringField("name",validators=[DataRequired()])
    email = EmailField("email",validators=[DataRequired(),Email()])
    age = IntegerField("age",validators=[DataRequired(),NumberRange(min = 18, max = 65)])
    submit = SubmitField("submit")
    