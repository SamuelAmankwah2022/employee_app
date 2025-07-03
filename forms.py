from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField
from wtforms.validators import DataRequired, Length, NumberRange

class LoginForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    school_name = StringField('School Name', validators=[DataRequired()])
    staff_id = StringField('Staff ID', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    school_name = StringField('School Name', validators=[DataRequired()])
    staff_id = StringField('Staff ID', validators=[DataRequired(), Length(min=4, max=50)])
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    bank_account_number = StringField('Bank Account Number', validators=[DataRequired()])
    submit = SubmitField('Register')

class AddEmployeeForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    school_name = StringField('School Name', validators=[DataRequired()])
    staff_id = StringField('Staff ID', validators=[DataRequired()])
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    bank_account_number = StringField('Bank Account Number', validators=[DataRequired()])
    submit = SubmitField('Add Employee')

class SalaryAdvanceRequestForm(FlaskForm):
    amount = FloatField('Amount', validators=[
        DataRequired(message="Amount is required."),
        NumberRange(min=1, message="Amount must be greater than zero.")
    ])
    reason = StringField('Reason', validators=[
        DataRequired(message="Reason is required."),
        Length(max=255)
    ])
    submit = SubmitField('Request Advance')

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EmployeeRegistrationForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    school_name = StringField('School Name', validators=[DataRequired()])
    staff_id = StringField('Staff ID', validators=[DataRequired()])
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    bank_account_number = StringField('Bank Account Number', validators=[DataRequired()])
    submit = SubmitField('Register Employee')