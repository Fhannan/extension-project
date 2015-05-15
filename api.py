from flask import *
import flask.ext.sqlalchemy
import flask.ext.restless
from datetime import datetime, timedelta
from flask_mail import Mail
import os
import pprint
from flask.ext.security import Security, SQLAlchemyUserDatastore,\
    UserMixin, RoleMixin, login_required, current_user, utils
from flask.ext.login import LoginManager
from forms import UpdateProfileForm
from sqlalchemy import event
import settings
from itsdangerous import URLSafeTimedSerializer
from celery_model import make_celery
from core_functions import url_extractor
from werkzeug.security import generate_password_hash, \
     check_password_hash
#from app import db
#from flask.ext.login import login_user, logout_user, current_user, login_required, LoginManager
#Create the Flask application and the Flask-SQLAlchemy object.
app = Flask(__name__)

app.config.from_object(settings)
##mail = Mail(app)

##db = flask.ext.sqlalchemy.SQLAlchemy(app)
##login_serializer = URLSafeTimedSerializer(app.secret_key)
##login_manager = LoginManager()

celery = make_celery(app)

@celery.task
def send_security_email(msg):
    # Use the Flask-Mail extension instance to send the incoming ``msg`` parameter
    # which is an instance of `flask_mail.Message`
    mail.send(msg)

@celery.task
def get_title_metadescription(url_id):
    lnk_obj = Link.query.get(url_id)
    lnk_obj.title = url_extractor(lnk_obj.url)['title']
    lnk_obj.meta_description = url_extractor(lnk_obj.url)['meta_description']
    db.session.commit()
    # Use the Flask-Mail extension instance to send the incoming ``msg`` parameter
    # which is an instance of `flask_mail.Message`
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column('password', db.String(256))
    email = db.Column('email', db.String(50), unique=True, index=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(255))
    current_login_ip = db.Column(db.String(255))
    login_count = db.Column(db.Integer)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    def __str__(self):
        return '<User id=%s email=%s>' % (self.id, self.email)

    def get_auth_token(self):
        #Encode a secure token for cookie
        data = [str(self.id), self.password]
        return login_serializer.dumps(data)


class Link(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Unicode)
    added_time = db.Column(db.DateTime, default=datetime.utcnow())
    title = db.Column(db.String(255))
    meta_description = db.Column(db.String(1024))


    # ================================================================
    # One-to-one (uselist=False) relationship between User and Link.
    owner_id = db.Column(db.Integer, db.ForeignKey('User.user.id'))
    owner = db.relationship('User', backref=db.backref('links',
                                                         lazy='dynamic'))


# Setup Flask-Security
##user_datastore = SQLAlchemyUserDatastore(db, User, Role)
##security = Security(app, user_datastore)

#create the database tables
db.create_all()
def after_insert_listener(mapper, connection, target):
    # 'target' is the inserted object
    #new_url = target.url
    url_id = target.id
    get_title_metadescription.delay(url_id)
event.listen(Link, 'after_insert', after_insert_listener)

@login_manager.token_loader
def load_token(token):
    max_age = app.config["REMEMBER_COOKIE_DURATION"].total_seconds()
    data = login_serializer.loads(token, max_age=max_age)
    #data[0] te user_id and data[1] e password ase
    user = User.query.get(data[0])
    if user and data[1] == user.password:
        return user
    return None

@security.send_mail_task
def delay_security_email(msg):
    send_security_email.delay(msg)

@app.route('/')
def home():
    return render_template("hello.html")

@app.route('/authkey')
def authkey():
    #pprint.pprint(flask.ext.security.core.UserMixin.get_auth_token())
    return current_user.get_auth_token()

@app.errorhandler(401)
def custom_401(error):
    return jsonify({'error':'email is not found'}),401

"""learn with headerhttp://stackoverflow.com/questions/7877230/standard-401-response-when-using-http-auth-in-flask
http://flask.pocoo.org/docs/api/#flask.Flask.errorhandler"""

@app.route('/api/loginto', methods = ['POST'])
def create_person():    
    if not request.json and not 'password' in request.json:
        abort(400)
    this_email = request.json.get('email')
    this_password = request.json.get('password')
    if User.query.filter(User.email == this_email).count() == 0:
        raise flask.ext.restless.ProcessingException(description='Not Authorized',
                                                     code=401)
    elif User.query.filter(User.email == this_email).count() == 1:
        u = User.query.filter(User.email == this_email)
        pwhash = u[0].password
        if u and utils.verify_password(this_password, pwhash):
            auth_token = u[0].get_auth_token()

    identity = {
        'email': this_email,
        'password':this_password,
       'authentication_token':auth_token
            }

    return jsonify( { 'identity': identity } )


@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    user = User.query.get(current_user.id)
    #pprint.pprint(user.first_name)
    form = UpdateProfileForm(request.form, obj=user)
    if request.method == 'POST' and form.validate() and current_user.is_authenticated():
        form.populate_obj(user)
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        db.session.commit()
        flash('your data has been updated')
        return redirect(url_for('home'))
    return render_template('profile_update.html', form=form)
# Create your Flask-SQLALchemy models as usual but with the following two

manager = flask.ext.restless.APIManager(app, flask_sqlalchemy_db=db)

def preprocessor_for_person(search_params=None, **kw):
    if search_params is None:
        return
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    person_id = request.args.get("person_id", "no_person_id")

    if len(request.args) == 0:
        search_params['filters'] = []
        search_params['filters'].append(filter_person_id)

    else:
        filter_start_date = {"name": "added_time", "op": "gte", "val": start_date}
        filter_end_date = {"name": "added_time", "op": "lte", "val": end_date}
        filter_person_id = {"name": "owner_id", "op": "eq", "val": person_id}

        # Check if there are any filters there already.
        if 'filters' not in search_params:
            search_params['filters'] = []
            # *Append* your filter to the list of filters.
            search_params['filters'].append(filter_start_date)
            search_params['filters'].append(filter_end_date)
            search_params['filters'].append(filter_person_id)

def preprocessor_for_link(search_params=None, **kw):
    if search_params is None:
        return
    auth_token = request.headers.get('Authorization')
    this_u = load_token(auth_token)
    if this_u:

        person_id = this_u.id
        filter_person_id = {"name": "owner_id", "op": "eq", "val": person_id}
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        if len(request.args) == 0:
            search_params['filters'] = []
            search_params['filters'].append(filter_person_id)
        else:
            filter_start_date = {"name": "added_time", "op": "gte", "val": start_date}
            filter_end_date = {"name": "added_time", "op": "lte", "val": end_date}
            if 'filters' not in search_params:
                search_params['filters'] = []
            search_params['filters'].append(filter_start_date)
            search_params['filters'].append(filter_end_date)
            search_params['filters'].append(filter_person_id)


def check_auth_token_in_header_post(data=None, **kw):
    NOW = datetime.utcnow()
    right = NOW
    left = NOW - timedelta(hours=24)
    auth_token = request.headers.get('Authorization')
    this_u = load_token(auth_token)
    if this_u:
        if Link.query.filter(Link.url == data['url'],
                         Link.added_time >= left,
                         Link.added_time <= right).count() > 0:

            raise flask.ext.restless.ProcessingException(description='Not Authorized',
                                                     code=409)
        else:
            data['owner_id'] = this_u.id

manager.create_api(Link, methods=['GET', 'POST', 'DELETE'],
                   url_prefix='/api/person_id',
                   preprocessors={
                       'GET_MANY': [preprocessor_for_person]}
)

manager.create_api(Link, methods=['GET', 'POST', 'DELETE'],
                   preprocessors={
                       'GET_MANY': [preprocessor_for_link],

                       'POST': [check_auth_token_in_header_post]
                                          },
                   include_columns=['url', 'owner_id', 'added_time', 'title', 'meta_description', 'id']
)
manager.create_api(User, methods=['GET', 'POST', 'DELETE'],
                   include_columns=['id', 'first_name', 'last_name', 'email' ])

manager.create_api(User, methods=['GET', 'POST', 'DELETE'],
                   url_prefix='/api/v2'

)

# start the flask loop




