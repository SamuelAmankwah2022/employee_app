import random
from models import Employee
from extensions import db

def generate_unique_pin_code():
    while True:
        pin = str(random.randint(100000, 999999))  # 6-digit PIN
        if not Employee.query.filter_by(pin_code=pin).first():
            return pin