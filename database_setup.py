from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
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

    id = Column(Integer, primary_key=True)
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

    id = Column(Integer, primary_key=True)
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
            'author_id': '         self.author_id
        }

    @property
    def serialize_with_description(self):
        """Return object data in easily serializeable format"""
        return {
            'item_title':          self.title,
            'item_id':             self.id,
            'category_id':         self.cat_id,
            'author_id': '         self.author_id,
            'description':         self.description
        }


engine = create_engine('sqlite:///Item_Catalog.db')

Base.metadata.create_all(engine)
