import urllib2
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from flask import *

def url_extractor(url):
    soup = BeautifulSoup(urllib2.urlopen(url).read())
    web_title = soup.find('title').string
    md = soup.findAll("meta", attrs={"name": "description"})[0]['content'].encode('utf-8')
    return dict(title=web_title, meta_description=md)

