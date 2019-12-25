from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import User, Item, Category, Base

engine = create_engine('sqlite:///Item_Catalog.db')
Base.metadata.bind = engine

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
