from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
import re
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import Email, DataRequired, EqualTo, ValidationError
from app.models import User


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    token = StringField('Token', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class PasswordValidationMixin:
    """
    A mixin to provide consistent, strong password validation logic
    to any form that includes a 'password' field.
    """
    def validate_password(self, password):
        pw = password.data
        errors = []
        if len(pw) < 8:
            errors.append("be at least 8 characters long")
        if not re.search(r'[a-z]', pw):
            errors.append("contain at least one lowercase letter")
        if not re.search(r'[A-Z]', pw):
            errors.append("contain at least one uppercase letter")
        if not re.search(r'\d', pw):
            errors.append("contain at least one number")
        if not re.search(r'[\W_]', pw):
            errors.append("contain at least one special character")

        if errors:
            raise ValidationError("Password must " + ", ".join(errors) + ".")

class RegistrationForm(FlaskForm, PasswordValidationMixin):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Choose a Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password')
                                                 ]
                                     )
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.get_by_username(username.data)
        if user is not None:
            raise ValidationError('Please use a different username')

    def validate_email(self, email):
        user = User.get_by_email(email.data)
        if user is not None:
            raise ValidationError('Please use a different email address')


class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save Note')


class FileUploadForm(FlaskForm):
    file = FileField('File', validators=[FileRequired()])
    submit = SubmitField('Upload')
    
class ResendVerificationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Resend Verification Email')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm, PasswordValidationMixin):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Request Password Reset')
