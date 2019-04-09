from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, IntegerField, DecimalField, DateField, \
    SelectField, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from flaskDemo import db
from flaskDemo.models import User, Department, Employee, Project, Works_On, getDepartment, getDepartmentFactory
from wtforms.fields.html5 import DateField

ssns = Department.query.with_entities(Department.mgr_ssn).distinct()
#  or could have used ssns = db.session.query(Department.mgr_ssn).distinct()
# for that way, we would have imported db from flaskDemo, see above

myChoices2 = [(row[0], row[0]) for row in ssns]  # change
results = list()
for row in ssns:
    rowDict = row._asdict()
    results.append(rowDict)
myChoices = [(row['mgr_ssn'], row['mgr_ssn']) for row in results]
regex1 = '^((((19|20)(([02468][048])|([13579][26]))-02-29))|((20[0-9][0-9])|(19[0-9][0-9]))-((((0[1-9])'
regex2 = '|(1[0-2]))-((0[1-9])|(1\d)|(2[0-8])))|((((0[13578])|(1[02]))-31)|(((0[1,3-9])|(1[0-2]))-(29|30)))))$'
regex = regex1 + regex2

# get employee ssn choices for add/update forms
employeessns = db.session.query(Employee.ssn)
employeessnchoices = [(row[0], row[0]) for row in employeessns]

# get project numbers for add/update forms
projectnos = db.session.query(Project.pnumber)
projectnochoices = [(row[0], row[0]) for row in projectnos]


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')


class DeptUpdateForm(FlaskForm):
    #    dnumber=IntegerField('Department Number', validators=[DataRequired()])
    dnumber = HiddenField("")

    dname = StringField('Department Name:', validators=[DataRequired(), Length(max=15)])
    #  Commented out using a text field, validated with a Regexp.  That also works, but a hassle to enter ssn.
    #    mgr_ssn = StringField("Manager's SSN", validators=[DataRequired(),Regexp('^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$', message="Please enter 9 digits for a social security.")])

    #  One of many ways to use SelectField or QuerySelectField.  Lots of issues using those fields!!
    mgr_ssn = SelectField("Manager's SSN", choices=myChoices)  # myChoices defined at top

    # the regexp works, and even gives an error message
    #    mgr_start=DateField("Manager's Start Date:  yyyy-mm-dd",validators=[Regexp(regex)])
    #    mgr_start = DateField("Manager's Start Date")

    #    mgr_start=DateField("Manager's Start Date", format='%Y-%m-%d')
    mgr_start = DateField("Manager's start date:", format='%Y-%m-%d')  # This is using the html5 date picker (imported)
    submit = SubmitField('Update this department')

    # got rid of def validate_dnumber

    def validate_dname(self, dname):  # apparently in the company DB, dname is specified as unique
        dept = Department.query.filter_by(dname=dname.data).first()
        if dept and (str(dept.dnumber) != str(self.dnumber.data)):
            raise ValidationError('That department name is already being used. Please choose a different name.')


class DeptForm(DeptUpdateForm):
    dnumber = IntegerField('Department Number', validators=[DataRequired()])
    submit = SubmitField('Add this department')

    def validate_dnumber(self, dnumber):  # because dnumber is primary key and should be unique
        dept = Department.query.filter_by(dnumber=dnumber.data).first()
        if dept:
            raise ValidationError('That department number is taken. Please choose a different one.')


class AssignUpdateForm(FlaskForm):
    pno = HiddenField("")
    essn = HiddenField("")
    hours = DecimalField('Hours Worked:', validators=[DataRequired()], places=1)
    submit = SubmitField('Add this assignment')

    def validate_assign(self, pno, essn):
        assign = (Works_On.query.filter_by(essn=essn.data).filter_by(pno=pno.data)).first()
        if assign and (str(assign.essn) != str(self.essn.data)) and (str(assign.pno) != str(self.pno.data)):
            raise ValidationError('That assignment already exists. Please create a unique one')


class AssignForm(AssignUpdateForm):

    pno = SelectField('Project Number:', coerce=int, choices=projectnochoices)
    essn = SelectField('Employee SSN:', choices=employeessnchoices)
    submit = SubmitField('Create this assignment')

    def validate_assign(self, pno, essn):
        assign = (Works_On.query.filter_by(essn=essn.data).filter_by(pno=pno.data)).first()
        if assign:
            raise ValidationError('That assignment already exists. Please create a unique one')

