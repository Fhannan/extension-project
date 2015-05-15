# -*- coding: utf-8 -*-
from flask import *
from sqlalchemy import Column, types
from sqlalchemy.ext.mutable import Mutable
from flask.ext.security import UserMixin, RoleMixin
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from collections import OrderedDict
from ..extensions import db, login_manager
from flask.ext.security import SQLAlchemyUserDatastore
import flask.ext.restless
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature


class DenormalizedText(Mutable, types.TypeDecorator):
    """
    Stores denormalized primary keys that can be
    accessed as a set.

    :param coerce: coercion function that ensures correct
                   type is returned

    :param separator: separator character
    """

    impl = types.Text

    def __init__(self, coerce=int, separator=" ", **kwargs):

        self.coerce = coerce
        self.separator = separator

        super(DenormalizedText, self).__init__(**kwargs)

    def process_bind_param(self, value, dialect):
        if value is not None:
            items = [str(item).strip() for item in value]
            value = self.separator.join(item for item in items if item)
        return value

    def process_result_value(self, value, dialect):
        if not value:
            return set()
        return set(self.coerce(item) for item in value.split(self.separator))

    def copy_value(self, value):
        return set(value)

login_serializer = URLSafeTimedSerializer('secret-key')

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

users_groups = db.Table('users_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)

links_categories = db.Table('links_categories',
    db.Column('link_id', db.Integer, db.ForeignKey('link.id')),
    db.Column('category_id', db.Integer, db.ForeignKey('category.id'))
)

links_groups = db.Table('links_groups',
    db.Column('link_id', db.Integer, db.ForeignKey('link.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)

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
    provider_access_token = db.Column(db.String(120))
    provider_id = db.Column(db.String(120))
    provider = db.Column(db.String(120))
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    groups = db.relationship('Group', secondary=users_groups,
                            backref=db.backref('users', lazy='dynamic'))
    invitations = db.relationship('Invitations',
                            backref=db.backref('users'))

    def __str__(self):
        return '<User id=%s email=%s>' % (self.id, self.email)


    def generate_auth_token(self):
        s = Serializer('super-secret')
        return s.dumps({ 'id': self.id })

    def _asdict(self):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = getattr(self, key)
        return result

class Link(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Unicode)
    added_time = db.Column(db.DateTime, default=datetime.utcnow())
    title = db.Column(db.Unicode, default=u'loading...')
    meta_description = db.Column(db.Unicode,default=u'loading...')

    # ================================================================
    # One-to-one (uselist=False) relationship between User and Link.
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = db.relationship('User', backref=db.backref('links',
                                                         lazy='dynamic'))
    categories = db.relationship('Category', secondary=links_categories,
                            backref=db.backref('links', lazy='dynamic'))
    groups = db.relationship('Group', secondary=links_groups,
                            backref=db.backref('links', lazy='dynamic'))
    # ================================================================
    def _asdict(self):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = getattr(self, key)
        return result

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_creation_date = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean())
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    link_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(255))

class Invitations(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column('email', db.String(50))
    invitation_date = db.Column(db.DateTime)
    accepted = db.Column(db.Boolean())
    invited_by = db.Column(db.Integer, db.ForeignKey('user.id'))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)

@login_manager.token_loader
def verify_auth_token(token):
    s = Serializer('super-secret')
    try:
        data = s.loads(token)
    except BadSignature:
        abort(401)
        #return None # invalid token
    user = user_datastore.get_user(data['id'])
    return user