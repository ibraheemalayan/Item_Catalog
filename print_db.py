from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

from database_setup import User, Item, Category, Base

def get_env_variable(name):
    try:
        return os.environ[name]
    except KeyError:
        message = "Expected environment variable '{}' not set.".format(name)
        raise Exception(message)

# the values of those depend on your setup
POSTGRES_URL = '127.0.0.1:5432'
POSTGRES_USER = 'postgres'
POSTGRES_PW = 'Grader@098'
POSTGRES_DB = 'item_catalog'

# Connect to Database and create database sessionmaker (DBSession)
engine = create_engine('postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB))
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)
db = DBSession()

users = db.query(User).all()

cats = db.query(Category).all()

items = db.query(Item).all()

print(" Users > \n\n")

for u in users:
    print("\n > " + str( u.serialize ))

print(" cats > \n\n")

for c in cats:
    print("\n > " + str( c.serialize ))

print(" Items > \n\n")

for i in items:
    print("\n > " + str( i.serialize ))

db.close()
