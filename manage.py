# -*- coding: utf-8 -*-

from flask.ext.script import Manager

from FlaskProject import create_app
from FlaskProject.extensions import db
from celery_model import make_celery
from datetime import datetime

from FlaskProject.user import User, Role, Link


app = create_app()
manager = Manager(app)
celery = make_celery(app)


@manager.command
def reset():
    """
    Reset local debug env.
    """

    local("rm -rf /tmp/instance")
    local("mkdir /tmp/instance")
    local("python manage.py initdb")

@manager.command
def run():
    """Run in local machine."""
    app.run(host='0.0.0.0')


@manager.command
def initdb():
    """Init/reset database."""
    db.drop_all()
    db.create_all()

manager.add_option('-c', '--config',
                   dest="config",
                   required=False,
                   help="config file")

if __name__ == "__main__":

    manager.run()
