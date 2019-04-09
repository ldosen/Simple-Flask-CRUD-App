import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from flaskDemo import app, db, bcrypt
from flaskDemo.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, DeptForm, DeptUpdateForm, \
    AssignForm, AssignUpdateForm
from flaskDemo.models import User, Post, Department, Dependent, Dept_Locations, Employee, Project, Works_On
from flask_login import login_user, current_user, logout_user, login_required
from datetime import datetime


@app.route("/")
@app.route("/home")
def home():
    results = Employee.query.join(Works_On, Employee.ssn == Works_On.essn).add_columns(Employee.fname,
                                                                                       Employee.lname).join(Project,
                                                                                                            Project.pnumber == Works_On.pno).add_columns(
        Works_On.pno, Works_On.essn, Works_On.hours, Project.pname)
    return render_template('assign_home.html', joined_m_n=results)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


@app.route("/dept/new", methods=['GET', 'POST'])
@login_required
def new_dept():
    form = DeptForm()
    if form.validate_on_submit():
        dept = Department(dname=form.dname.data, dnumber=form.dnumber.data, mgr_ssn=form.mgr_ssn.data,
                          mgr_start=form.mgr_start.data)
        db.session.add(dept)
        db.session.commit()
        flash('You have added a new department!', 'success')
        return redirect(url_for('home'))
    return render_template('create_dept.html', title='New Department',
                           form=form, legend='New Department')


@app.route("/dept/<dnumber>")
@login_required
def dept(dnumber):
    dept = Department.query.get_or_404(dnumber)
    return render_template('dept.html', title=dept.dname, dept=dept, now=datetime.utcnow())


@app.route("/dept/<dnumber>/update", methods=['GET', 'POST'])
@login_required
def update_dept(dnumber):
    dept = Department.query.get_or_404(dnumber)
    currentDept = dept.dname

    form = DeptUpdateForm()
    if form.validate_on_submit():  # notice we are are not passing the dnumber from the form
        if currentDept != form.dname.data:
            dept.dname = form.dname.data
        dept.mgr_ssn = form.mgr_ssn.data
        dept.mgr_start = form.mgr_start.data
        db.session.commit()
        flash('Your department has been updated!', 'success')
        return redirect(url_for('dept', dnumber=dnumber))
    elif request.method == 'GET':
        form.dnumber.data = dept.dnumber  # notice that we ARE passing the dnumber to the form
        form.dname.data = dept.dname
        form.mgr_ssn.data = dept.mgr_ssn
        form.mgr_start.data = dept.mgr_start
    return render_template('update_dept.html', title='Update Department',
                           form=form, legend='Update Department')  # note the update template!


@app.route("/dept/<dnumber>/delete", methods=['POST'])
@login_required
def delete_dept(dnumber):
    dept = Department.query.get_or_404(dnumber)
    db.session.delete(dept)
    db.session.commit()
    flash('The department has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/assign/<pno>/<essn>")
@login_required
def assign(pno, essn):
    assign = Works_On.query.get_or_404([essn, pno])
    return render_template('assign.html', title=str(assign.essn) + "_" + str(assign.pno), assign=assign,
                           now=datetime.utcnow())


@app.route("/assign/<pno>/<essn>/delete", methods=['POST'])
@login_required
def delete_assign(pno, essn):
    assign = Works_On.query.get_or_404([essn, pno])
    db.session.delete(assign)
    db.session.commit()
    flash('The assignment has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/assign/new", methods=['GET', 'POST'])
@login_required
def add_assign():
    form = AssignForm()
    if form.validate_on_submit():
        assign = Works_On(essn=form.essn.data, pno=form.pno.data, hours=form.hours.data)
        db.session.add(assign)
        db.session.commit()
        flash('You have added a new assignment!', 'success')
        return redirect(url_for('home'))
    return render_template('create_assign.html', title='New Assignment',
                           form=form, legend='New Assignment')


@app.route("/assign/<pno>/<essn>/update", methods=['GET', 'POST'])
@login_required
def update_assign(pno, essn):

    assign = Works_On.query.get_or_404([essn, pno])
    currentHours = assign.hours

    form = AssignUpdateForm()
    if form.validate_on_submit():
        if currentHours != form.hours.data:
            assign.hours = form.hours.data
            db.session.commit()
            flash('The assignment has been updated!', 'success')
            return redirect(url_for('assign', essn=essn, pno=pno))
    elif request.method == 'GET':
        form.pno.data = assign.pno
        form.essn.data = assign.essn
        form.hours.data = assign.hours
    return render_template('update_assign.html', title='Update Assignment',
                           form=form, legend='Update Assignment')
