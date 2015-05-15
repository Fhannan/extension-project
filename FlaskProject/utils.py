# -*- coding: utf-8 -*-
"""
    Utils has nothing to do with models and views.
"""


import os

from datetime import datetime
import string, random

import urllib2
from bs4 import BeautifulSoup



# Instance folder path, make it independent.
INSTANCE_FOLDER_PATH = os.path.join('/tmp', 'instance')

"""def url_extractor(url):
    soup = BeautifulSoup(urllib2.urlopen(url).read())
    web_title = soup.find('title').string
    md = soup.findAll("meta", attrs={"name": "description"})[0]['content'].encode('utf-8')
    return dict(title=web_title, meta_description=md)"""

def get_current_time():
    return datetime.utcnow()

def make_dir(dir_path):
    try:
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
    except Exception, e:
        raise e

def password_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))



