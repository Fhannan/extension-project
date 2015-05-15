import sys
import os
import wsgi_monitor

#sys.path.insert(0, '/home/mahbub/www/flask/flask-restless')
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
wsgi_monitor.start(interval=1.0)
from api import app as application
