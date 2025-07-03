from sqlalchemy import UniqueConstraint
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from extensions import db

# Admin model with password (keep this as-is)
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password_hash = db.Column(db.String(256))  # or 512 to be safe

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return f"admin:{self.id}"


# ✅ Employee model WITHOUT password (we remove the password column and logic)
class Employee(UserMixin, db.Model):
    __tablename__ = 'employee'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    school_name = db.Column(db.String(150), nullable=False)
    staff_id = db.Column(db.String(100), unique=True, nullable=False)
    bank_name = db.Column(db.String(100))
    bank_account_number = db.Column(db.String(50))
    pin_code = db.Column(db.String(10), nullable=False)

    __table_args__ = (
        UniqueConstraint('pin_code', name='uq_employee_pin_code'),
    )

    def get_id(self):
        return f"employee:{self.id}"
# Salary Advance Request model (no change needed here)
class SalaryAdvanceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    amount = db.Column(db.Float)
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

    consent_given = db.Column(db.Boolean, default=False)
    consent_date = db.Column(db.DateTime)
    signed_name = db.Column(db.String(150))

    employee = db.relationship('Employee', backref='salary_requests')