import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, Length, EqualTo, ValidationError


def character_check(form,field):
    excluded_chars = "*?"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(
                f"Character {char} is not allowed.")

class RegisterForm(FlaskForm):
    # format for user registration
    email = StringField(validators=[Required(), Email()])
    firstname = StringField(validators=[Required()])
    lastname = StringField(validators=[Required()])
    phone = StringField(validators=[Required()])
    password = PasswordField(validators=[Required(), Length(min=6, max=12, message='Password must be between 6 and 12 characters in length.'), character_check])
    confirm_password = PasswordField(validators=[Required(), EqualTo('password', message='Both password fields must be equal!')])
    pin_key = StringField(validators=[Required(), Length(min=32, max=32, message='pin key must be 32 characters in length.')])
    submit = SubmitField()

    def validate_firstname(self, firstname):
        # Exclusion of special characters within firstname input
        p = re.compile(r'(?=.*\d)(?=.*[@_!#$%^&*()<>?/\|}{~:])')
        # Return error if excluded characters found
        if p.match(self.firstname.data):
            raise ValidationError("First name must not contain at any digits or special characters")

    def validate_lastname(self, lastname):
        # Exclusion of special characters within lastname input
        p = re.compile(r'(?=.*\d)(?=.*[@_!#$%^&*()<>?/\|}{~:])')
        # return error if excluded characters found
        if p.match(self.lastname.data):
            raise ValidationError("Last name must not contain at any digits or special characters")

    def validate_phone(self, phone):
        # formatting for phone number
        p = re.compile(r'(^\d{4}-\d{3}-\d{4}$)')
        if not p.match(self.phone.data):
            raise ValidationError("Phone number must be in correct format XXXX-XXX-XXXX")

    def validate_password(self, password):
        # determine if password includes required digit, uppercase letter, lowercase letter and special character
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[@_!#$%^&*()<>?/\|}{~:])')
        if not p.match(self.password.data):
            raise ValidationError("Password must contain at least 1 digit, 1 uppercase letter, 1 lowercase letter and 1 special character.")

class LoginForm(FlaskForm):
    email = StringField(validators=[Required(), Email()])
    password = PasswordField(validators=[Required()])
    pin_key = StringField(validators=[Required()])
    submit = SubmitField()