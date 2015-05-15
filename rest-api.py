import sys
import os
#from app import db
from api import app as application
application.run(host = '0.0.0.0')
