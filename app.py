
import os
from datetime import datetime
from functools import wraps
from sqlalchemy import extract
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Flask-related imports
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, make_response
)
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from flask_migrate import Migrate

# PDF library


# Local modules
from extensions import db, login_manager
from models import Employee, Admin, SalaryAdvanceRequest
from forms import (
    LoginForm, RegisterForm, AddEmployeeForm,
    SalaryAdvanceRequestForm, AdminLoginForm
)
from utils import generate_unique_pin_code

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
# ✅ Admin-only route decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not isinstance(current_user, Admin):
            flash("Access denied: Admins only.", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function

# Init extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)
@app.route('/view_request/<int:request_id>')
@login_required
def view_request(request_id):
    salary_request = SalaryAdvanceRequest.query.get_or_404(request_id)
    return render_template('view_request.html', request=salary_request)
@app.route('/thank_you')
def thank_you():
    return render_template('thank_you.html')
@app.route('/request/<int:request_id>')
def public_view_request(request_id):  # ✅ Renamed function
    request_obj = SalaryAdvanceRequest.query.get_or_404(request_id)
    return render_template('view_request.html', request=request_obj)
@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith("admin:"):
        real_id = int(user_id.split(":")[1])
        return db.session.get(Admin, real_id)  # ✅ recommended
    elif user_id.startswith("employee:"):
        real_id = int(user_id.split(":")[1])
        return db.session.get(Employee, real_id)  # ✅ recommended
@app.route('/')
def home():
    if current_user.is_authenticated:
        if isinstance(current_user, Admin):
            return redirect(url_for('admin_dashboard'))
        elif isinstance(current_user, Employee):
            return redirect(url_for('employee_dashboard'))
    # Instead of going directly to login, redirect to pin first
    return redirect(url_for('enter_pin'))
@app.route('/enter_pin', methods=['GET', 'POST'])
def enter_pin():
    if request.method == 'POST':
        pin_code = request.form.get('pin_code', '').strip()

        employee = Employee.query.filter_by(pin_code=pin_code).first()
        if employee:
            session['pin_verified'] = pin_code  # Store temporarily
            return redirect(url_for('employee_login'))
        else:
            flash('Invalid PIN code.', 'danger')

    return render_template('enter_pin.html')
@app.route('/employee/login', methods=['GET', 'POST'])
def employee_login():
    # STEP 1: Block access if no valid pin was entered
    if 'pin_verified' not in session:
        flash('Please enter your PIN code first.', 'warning')
        return redirect(url_for('enter_pin'))

    # STEP 2: Proceed to login
    form = LoginForm()
    if form.validate_on_submit():
        full_name = form.full_name.data.strip()
        school_name = form.school_name.data.strip()
        staff_id = form.staff_id.data.strip()

        employee = Employee.query.filter_by(
            full_name=full_name,
            school_name=school_name,
            staff_id=staff_id
        ).first()

        if employee:
            login_user(employee)
            session.pop('pin_verified', None)  # 🔒 Clear the PIN from session after login
            flash(f"Welcome {employee.full_name}!", 'success')
            return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('employee_login.html', form=form)
@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    if isinstance(current_user, Employee):
        return render_template('employee_dashboard.html', current_user=current_user)
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin and admin.check_password(form.password.data):
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials.', 'danger')
    return render_template('admin_login.html', form=form)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if isinstance(current_user, Admin):
        employees = Employee.query.all()
        return render_template('admin_dashboard.html', employees=employees)
    return redirect(url_for('employee_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        staff_id = form.staff_id.data
        school_name = form.school_name.data

        employee = Employee.query.filter_by(staff_id=staff_id, school_name=school_name).first()
        if employee:
            login_user(employee)
            return redirect(url_for('home'))
        else:
            flash('Invalid staff ID or school name.')
    return render_template('login.html', form=form)
@app.route('/logout')
@login_required
def logout():
    session.pop('pin_verified', None)  # 🧹 Remove pin_verified from session
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('enter_pin'))  # 👈 Redirect to pin entry, not login
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_employee = Employee(
            full_name=form.full_name.data,
            school_name=form.school_name.data,
            staff_id=form.staff_id.data,
            bank_name=form.bank_name.data,
            bank_account_number=form.bank_account_number.data
        )
        new_employee.set_password(form.password.data)
        db.session.add(new_employee)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('employee_login'))
    return render_template('register.html', form=form)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_employee():
    if not isinstance(current_user, Admin):
        flash('Access denied: Admins only.')
        return redirect(url_for('home'))

    form = AddEmployeeForm()
    if form.validate_on_submit():
        staff_id = form.staff_id.data.strip()

        # Auto-generate password (same as staff ID or rule-based)
        generated_password = staff_id  
        hashed_password = generate_password_hash(generated_password)

        # ✅ Generate unique pin code here
        unique_pin = generate_unique_pin_code()

        new_emp = Employee(
            full_name=form.full_name.data.strip(),
            school_name=form.school_name.data.strip(),
            staff_id=staff_id,
            bank_name=form.bank_name.data.strip(),
            bank_account_number=form.bank_account_number.data.strip(),
            
            pin_code=unique_pin  # ✅ Assign the generated pin
        )

        db.session.add(new_emp)
        db.session.commit()
        flash(f'Employee added successfully. Pin: {unique_pin}')  # Optional: show pin
        return redirect(url_for('home'))

    return render_template('add_employee.html', form=form)            
@app.route('/consent_form/<int:request_id>', methods=['GET', 'POST'])
@login_required
def consent_form(request_id):
    salary_request = SalaryAdvanceRequest.query.get_or_404(request_id)
    employee = Employee.query.get_or_404(salary_request.employee_id)

    if request.method == 'POST':
        if request.form.get("agree") == "on":
            signed_name = request.form.get("signed_name") or employee.full_name  # Fallback

            salary_request.consent_given = True
            salary_request.consent_date = datetime.utcnow()
            salary_request.signed_name = signed_name

            db.session.commit()
            flash("Consent submitted successfully.", "success")
            return redirect(url_for('thank_you'))
        else:
            flash("You must agree to the terms before submitting.", "danger")

    # ✅ Pass current_date to template
    return render_template(
        'consent_form.html',
        request=salary_request,
        employee=employee,
        current_date=datetime.utcnow()
    )
@app.route('/request_advance', methods=['GET', 'POST'])
@login_required
def request_advance():
    if request.method == 'POST':
        amount = float(request.form['amount'])

        if amount < 200 or amount > 500:
            flash("Amount must be between 200 and 500 cedis.", "danger")
            return render_template('request_advance.html')

        new_request = SalaryAdvanceRequest(
            employee_id=current_user.id,
            amount=amount,
            date_submitted=datetime.utcnow(),
            status='Pending'
        )
        db.session.add(new_request)
        db.session.commit()

        return redirect(url_for('consent_form', request_id=new_request.id))

    return render_template('request_advance.html')
@app.route('/salary_requests')
@login_required
@admin_required
def view_salary_requests():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()

    query = SalaryAdvanceRequest.query.join(Employee)

    if search:
        query = query.filter(
            db.or_(
                Employee.full_name.ilike(f"%{search}%"),
                Employee.staff_id.ilike(f"%{search}%"),
                Employee.school_name.ilike(f"%{search}%")
            )
        )

    requests_paginated = query.order_by(SalaryAdvanceRequest.date_submitted.desc()).paginate(page=page, per_page=10)
    
    return render_template('view_salary_requests.html', requests=requests_paginated, search=search)
@app.route('/approve/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    if not isinstance(current_user, Admin):
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('employee_dashboard'))

    req = SalaryAdvanceRequest.query.get_or_404(request_id)
    req.status = 'Approved'
    db.session.commit()
    flash('Request approved.', 'success')
    return redirect(url_for('view_salary_requests'))

@app.route('/reject/<int:request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    if not isinstance(current_user, Admin):
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('employee_dashboard'))

    req = SalaryAdvanceRequest.query.get_or_404(request_id)
    req.status = 'Rejected'
    db.session.commit()
    flash('Request rejected.', 'info')
    return redirect(url_for('view_salary_requests'))
@app.route('/admin/consents')
@admin_required
def view_consents():
    month = request.args.get('month', type=int)
    year = request.args.get('year', type=int)

    if not month or not year:
        flash("Please select a valid month and year.", "warning")
        return render_template('admin/consents_filter.html')

    consents = SalaryAdvanceRequest.query.filter(
        SalaryAdvanceRequest.consent_given == True,
        extract('month', SalaryAdvanceRequest.consent_date) == month,
        extract('year', SalaryAdvanceRequest.consent_date) == year
    ).order_by(SalaryAdvanceRequest.consent_date.desc()).all()

    return render_template('admin/consents_list.html', consents=consents, month=month, year=year)
@app.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
@admin_required  # ✅ Restricts access to admins only
def change_admin_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_user.check_password(current_password):
            flash("Current password is incorrect.", "danger")
        elif new_password != confirm_password:
            flash("New passwords do not match.", "warning")
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash("Password updated successfully.", "success")
            return redirect(url_for('admin_dashboard'))

    return render_template('admin/change_password.html')
@app.route('/delete/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def delete_request(request_id):
    req = SalaryAdvanceRequest.query.get_or_404(request_id)
    db.session.delete(req)
    db.session.commit()
    flash('Request deleted successfully.', 'info')
    return redirect(url_for('view_salary_requests'))
@app.route('/edit/<int:request_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_request(request_id):
    request_obj = SalaryAdvanceRequest.query.get_or_404(request_id)

    if request.method == 'POST':
        new_amount = float(request.form.get('amount'))
        new_reason = request.form.get('reason')

        if not (200 <= new_amount <= 500):
            flash("Amount must be between GHS 200 and 500.", "danger")
        else:
            request_obj.amount = new_amount
            request_obj.reason = new_reason
            db.session.commit()
            flash("Request updated successfully.", "success")
            return redirect(url_for('view_salary_requests'))

    return render_template('admin/edit_request.html', request_obj=request_obj)
@app.route('/admin/delete_employee/<int:employee_id>', methods=['POST'])
@login_required
@admin_required
def delete_employee(employee_id):
    employee = Employee.query.get_or_404(employee_id)
    db.session.delete(employee)
    db.session.commit()
    flash("Employee deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/edit_employee/<int:employee_id>', methods=['GET', 'POST'])
@admin_required
def edit_employee(employee_id):
    employee = Employee.query.get_or_404(employee_id)

    if request.method == 'POST':
        employee.full_name = request.form['full_name']
        employee.school_name = request.form['school_name']
        employee.staff_id = request.form['staff_id']
        employee.bank_name = request.form['bank_name']
        employee.bank_account_number = request.form['bank_account_number']

        db.session.commit()
        flash('Employee details updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/edit_employee.html', employee=employee)
@app.route('/download_consent/<int:request_id>')
@login_required
def download_consent(request_id):
    salary_request = SalaryAdvanceRequest.query.get_or_404(request_id)
    employee = salary_request.employee

    # Render the consent form HTML with data
    html = render_template('consent_form_pdf.html', request=salary_request, employee=employee, current_date=datetime.utcnow())

    # Generate the PDF
    pdf = HTML(string=html).write_pdf()

    # Return the PDF as a downloadable response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=consent_form_{employee.staff_id}.pdf'

    return response
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not Admin.query.filter_by(username='admin').first():
            test_admin = Admin(
                username='admin',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(test_admin)
            db.session.commit()
            print("Admin created: admin / admin123")
        else:
            print("Admin already exists.")

    app.run(debug=True)