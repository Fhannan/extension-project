# -*- coding: utf-8 -*-

from flask import *
from flask.ext.login import login_required
from flask.ext.security import SQLAlchemyUserDatastore, roles_required, current_user
import pprint
from ..extensions import db
from ..user import User, Role, Link
from .forms import CreateAdmin
from datetime import datetime,timedelta, date
from sqlalchemy import Date, cast, or_

admin = Blueprint('admin', __name__, url_prefix='/admin')

user_datastore = SQLAlchemyUserDatastore(db, User, Role)

@admin.route('/create_admin',methods=['GET', 'POST'])
@login_required
def create_admin():

    form = CreateAdmin(request.form)
    if request.method == 'POST' and form.validate() and current_user.is_authenticated():
        get_email = form.email.data
        user = user_datastore.find_user(email=get_email)
        role = user_datastore.find_role('Admin')
        if user == None:
            flash('no user is found with this email address','warning')
            return redirect(url_for('admin.create_admin'))
        elif not role == None:
            flash('admin already been created','danger')
            return redirect(url_for('admin.create_admin'))
        createRole = user_datastore.create_role(name='Admin', description='this email is allocated for Admin only')
        db.session.add(createRole)
        db.session.commit()
        user = user_datastore.find_user(email=get_email)
        role = user_datastore.find_role('Admin')
        user_datastore.add_role_to_user(user, role)
        db.session.commit()
        flash('this provided email has become admin','success')
        return redirect(url_for('admin.create_admin'))
    return render_template('admin/create_admin.html', form=form)

@admin.route('/')
@login_required
@roles_required('Admin')
def index():
    return render_template('admin/index.html')

@admin.route('/show_links')
@login_required
@roles_required('Admin')
def show_links():
    dict_col = {'0':'url',
                '1':'added_time',
                '2':'title',
                '3':'meta_description',
                '4':'owner_id'}
    start_date = request.args.get('datebox[start_date]')
    end_date = request.args.get('datebox[end_date]')
    s_val = request.args.get('search[value]')
    col_no = request.args.get('order[0][column]')
    order_dir = request.args.get('order[0][dir]')
    pageStart = request.args.get('start')
    pageLen = request.args.get('length')

    if (start_date =="" or start_date is None) and (end_date =="" or end_date is None):
        qry = Link.query.\
                     filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%"))).\
                     order_by(dict_col[col_no]+" "+order_dir).\
                     offset(pageStart).\
                     limit(pageLen).\
                     all()
        qry_count = Link.query.filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%"))).count()

    if not (start_date is None) and not (end_date is None) and start_date==end_date:
        #temp = datetime.strptime(start_date, '%Y-%m-%d').date()
        #end_date = temp + timedelta(days=1)
        #pprint.pprint(temp)
        qry = Link.query.\
                     filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), cast(Link.added_time,Date) == date.today()).\
                     order_by(dict_col[col_no]+" "+order_dir).\
                     offset(pageStart).\
                     limit(pageLen).\
                     all()

        qry_count = Link.query.filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), cast(Link.added_time,Date) == date.today()).count()

    if start_date != end_date:
        qry = Link.query.\
                        filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), Link.added_time >= start_date, Link.added_time <= end_date).\
                        order_by(dict_col[col_no]+" "+order_dir).\
                        offset(pageStart).\
                        limit(pageLen).\
                        all()

        qry_count = Link.query.filter(or_(Link.title.like("%"+s_val+"%"), Link.meta_description.like("%"+s_val+"%"), Link.url.like("%"+s_val+"%")), Link.added_time >= start_date, Link.added_time <= end_date).count()



    return json.dumps({'recordsTotal':Link.query.count(),'recordsFiltered':qry_count,'data':list(qry)})


@admin.route('/show_users')
@login_required
@roles_required('Admin')
def show_users():
    dict_col = {'0':'email',
                '1':'first_name',
                '2':'last_name'
                }
    start_date = request.args.get('datebox[start_date]')
    end_date = request.args.get('datebox[end_date]')
    s_val = request.args.get('search[value]')
    col_no = request.args.get('order[0][column]')
    order_dir = request.args.get('order[0][dir]')
    pageStart = request.args.get('start')
    pageLen = request.args.get('length')
    if (start_date =="" or start_date is None) and (end_date =="" or end_date is None):
        qry = User.query.\
                     filter(User.email.like("%"+s_val+"%")).\
                     order_by(dict_col[col_no]+" "+order_dir).\
                     offset(pageStart).\
                     limit(pageLen).\
                     all()
        qry_count = User.query.filter(User.email.like("%"+s_val+"%")).count()
    else:
        qry = User.query.\
                     filter(User.email.like("%"+s_val+"%"), User.confirmed_at >= start_date, User.confirmed_at <= end_date).\
                     order_by(dict_col[col_no]+" "+order_dir).\
                     offset(pageStart).\
                     limit(pageLen).\
                     all()

        qry_count = User.query.filter(User.email.like("%"+s_val+"%"), User.confirmed_at >= start_date, User.confirmed_at <= end_date).count()

    return json.dumps({'recordsTotal':User.query.count(),'recordsFiltered':qry_count,'data':list(qry)})

@admin.route('/all_links')
@login_required
@roles_required('Admin')
def all_links():
    today = datetime.utcnow().strftime('%Y-%m-%d')

    return render_template('admin/links.html',today = today)

@admin.route('/all_users')
def all_users():
    today = datetime.utcnow().strftime('%Y-%m-%d')
    return render_template('admin/users.html',today = today)

