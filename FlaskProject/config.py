# -*- coding: utf-8 -*-

import os

from utils import make_dir, INSTANCE_FOLDER_PATH
from datetime import datetime, timedelta


class BaseConfig(object):

    PROJECT = "FlaskProject"

    # Get app root path, also can use flask.root_path.
    # ../../config.py
    #PROJECT_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

    #DEBUG = False
    #TESTING = False

    #ADMINS = ['youremail@yourdomain.com']

    # http://flask.pocoo.org/docs/quickstart/#sessions
    SECRET_KEY = 'super-secret'

    #LOG_FOLDER = os.path.join(INSTANCE_FOLDER_PATH, 'logs')
    #make_dir(LOG_FOLDER)

    # Fild upload, should override in production.
    # Limited the maximum allowed payload to 16 megabytes.
    # http://flask.pocoo.org/docs/patterns/fileuploads/#improving-uploads
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    #UPLOAD_FOLDER = os.path.join(INSTANCE_FOLDER_PATH, 'uploads')
    #make_dir(UPLOAD_FOLDER)


class DefaultConfig(BaseConfig):

    DEBUG = True

    PROJECT_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    # Flask-Sqlalchemy: http://packages.python.org/Flask-SQLAlchemy/config.html
    SQLALCHEMY_ECHO = True
    # SQLITE for prototyping.
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + PROJECT_ROOT + '/db/db.sqlite'
    # MYSQL for production.
    #SQLALCHEMY_DATABASE_URI = 'mysql://username:password@server/db?charset=utf8'

    # Flask-babel: http://pythonhosted.org/Flask-Babel/
    ACCEPT_LANGUAGES = ['zh']
    BABEL_DEFAULT_LOCALE = 'en'

    # Flask-cache: http://pythonhosted.org/Flask-Cache/
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 60

    # Flask-mail: http://pythonhosted.org/flask-mail/
    # https://bitbucket.org/danjac/flask-mail/issue/3/problem-with-gmails-smtp-server
    MAIL_DEBUG = DEBUG
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'ferdous@ivivelabs.com'
    MAIL_PASSWORD = 'RiskFactor12'
    FB_CLIENT_ID = '1410369132585882'
    FB_CLIENT_SECRET = '6f200e2a3b933c8567d7fdcd19620f2e'

    # Should put MAIL_USERNAME and MAIL_PASSWORD in production under instance folder.

    SECRET_KEY = 'super-secret'
    DEFAULT_MAIL_SENDER = 'info@site.com'
    SECURITY_REGISTERABLE = True
    SECURITY_CONFIRMABLE = True
    SECURITY_RECOVERABLE = True
    SECURITY_CHANGEABLE = True
    SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
    SECURITY_PASSWORD_SALT = 'MD5'
    SECURITY_TRACKABLE = True
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    SECURITY_TOKEN_AUTHENTICATION_HEADER = 'Authentication-Token'
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    FB_CLIENT_ID='1410369132585882'
    FB_CLIENT_SECRET='6f200e2a3b933c8567d7fdcd19620f2e'




