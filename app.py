import os
from datetime import datetime, timezone  # ✅ updated to include timezone
from functools import wraps
from sqlalchemy import extract
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from alembic.command import upgrade
from alembic.config import Config
from forms import SalaryAdvanceRequestForm  # ✅ Import your form
from forms import PinCodeForm  # ✅ Make sure this is imported
from forms import ConsentForm  # ✅ Make sure this is at the top if not already
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
from flask_wtf import CSRFProtect  # ✅ last of flask-related imports
import logging
from logging.handlers import RotatingFileHandler
import os
# PDF library (if needed)
import requests  # ✅ Add here

def is_ghana_ip(ip_address):
    try:
        response = requests.get(f"https://ipapi.co/{ip_address}/country_name/")
        if response.status_code == 200:
            country = response.text.strip()
            return country.lower() == "ghana"
    except Exception as e:
        print(f"Geolocation check failed: {e}")
    return False

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

# ✅ Set up logging (right after creating the app)
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=5)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('App startup')


# ✅ Restrict non-Ghana visitors
@app.before_request
def block_non_ghana_visitors():
    # Allow local dev IPs like 127.0.0.1 or ::1
    if request.remote_addr in ('127.0.0.1', '::1'):
        return

    # Skip IP check for static files and favicon
    if request.endpoint in ('static',):
        return

    if not is_ghana_ip(request.remote_addr):
        app.logger.warning(f"Blocked IP: {request.remote_addr}")
        return render_template('access_denied.html'), 403
# ✅ Manually set the secret key for session and CSRF protection
app.secret_key ='gfh34@!kdj983laksdnjgfh304nvks'


csrf = CSRFProtect(app)  #

# ✅ If you're using environment variables for the database, keep this line
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
    form = PinCodeForm()
    if form.validate_on_submit():
        pin_code = form.pin_code.data.strip()

        employee = Employee.query.filter_by(pin_code=pin_code).first()
        if employee:
            session['pin_verified'] = pin_code  # Store temporarily
            return redirect(url_for('employee_login'))
        else:
            flash('Invalid PIN code.', 'danger')

    return render_template('enter_pin.html', form=form)
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
        latest_request = SalaryAdvanceRequest.query.filter_by(employee_id=current_user.id).order_by(SalaryAdvanceRequest.date_submitted.desc()).first()
        return render_template('employee_dashboard.html', current_user=current_user, latest_request=latest_request)
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
@app.route('/request_advance', methods=['GET', 'POST'])
@login_required
def request_advance():
    form = SalaryAdvanceRequestForm()
    if form.validate_on_submit():
        amount = form.amount.data
        reason = form.reason.data

        new_request = SalaryAdvanceRequest(
            employee_id=current_user.id,
            amount=amount,
            reason=reason,
            date_submitted=datetime.utcnow(),
            status='Pending'
        )
        db.session.add(new_request)
        db.session.commit()

        return redirect(url_for('consent_form', request_id=new_request.id))

    return render_template('request_advance.html', form=form)
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
@app.route('/consent_form/<int:request_id>', methods=['GET', 'POST'])
@login_required
def consent_form(request_id):
    salary_request = SalaryAdvanceRequest.query.get_or_404(request_id)
    employee = Employee.query.get_or_404(salary_request.employee_id)

    form = ConsentForm()

    if form.validate_on_submit():
        salary_request.consent_given = True
        salary_request.consent_date = datetime.utcnow()
        salary_request.signed_name = form.signed_name.data or employee.full_name

        db.session.commit()
        flash("Consent submitted successfully.", "success")
        return redirect(url_for('thank_you'))
    elif request.method == 'GET':
        form.signed_name.data = employee.full_name  # Pre-fill hidden field

    return render_template(
        'consent_form.html',
        form=form,
        request=salary_request,
        employee=employee,
        current_date=datetime.utcnow()
    )
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
admin_created = False  # ✅ Define the flag before the route or request hook

@app.before_request
def create_test_admin_once():
    global admin_created
    if not admin_created:
        existing_admin = Admin.query.filter_by(username="admin").first()
        if not existing_admin:
            test_admin = Admin(
                username="admin",
                password=generate_password_hash("admin123", method="pbkdf2:sha256", salt_length=16)
            )
            db.session.add(test_admin)
            db.session.commit()
            print("✅ Test admin created: username=admin, password=admin123")
        else:
            print("ℹ️ Test admin already exists.")
        admin_created = True
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500
if __name__ == "__main__":
    app.run(debug=False)