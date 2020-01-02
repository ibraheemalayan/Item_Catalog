from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.sql import func
import os

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(250), nullable=False)
    picture = Column(String(500))
    email = Column(String(100), nullable=False)
    password_hash = Column(String(65))
    sec_q = Column(String(100))
    sec_a = Column(String(100))

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name':          self.name,
            'id':            self.id,
            'picture':       self.picture,
            'email':         self.email
        }


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80), nullable=False)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'category_name':        self.name,
            'category_id':          self.id
        }


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(100), nullable=False)
    description = Column(String(1000), nullable=False)
    author_id = Column(Integer, ForeignKey('user.id'))
    author = relationship(User)
    cat_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category, single_parent=True)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'item_title':          self.title,
            'item_id':             self.id,
            'category_id':         self.cat_id,
            'author_id':           self.author_id
        }

    @property
    def serialize_with_description(self):
        """Return object data in easily serializeable format"""
        return {
            'item_title':          self.title,
            'item_id':             self.id,
            'category_id':         self.cat_id,
            'author_id':           self.author_id,
            'description':         self.description
        }


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

engine = create_engine('postgresql://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB))
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)

# Sequence for IDs
db = DBSession()

max_item = str(db.query(func.max(Item.id)).one())[1:-2]
max_cat = str(db.query(func.max(Category.id)).one())[1:-2]
max_user = str(db.query(func.max(User.id)).one())[1:-2]

if max_item =='None':
    max_item = '0'


if max_cat =='None':
    max_cat = '0'

if max_user =='None':
    max_user = '0'

new_item_id = int(max_item) + 1
new_cat_id = int(max_cat) + 1
new_user_id = int(max_user) + 1

db.execute("SELECT setval('item_id_seq', " + str(new_item_id) + ", false);")
db.execute("SELECT setval('category_id_seq', " + str(new_cat_id)+ ", false);")
db.execute("SELECT setval('user_id_seq', " + str(new_user_id) + ", false);")

db.commit()
db.close()
