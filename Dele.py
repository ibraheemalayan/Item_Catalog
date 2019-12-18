from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import User, Base

engine = create_engine('sqlite:///Item_Cataolg.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

user = session.query(User).filter_by(email='ibraheemalayan@gmail.com').one()
session.delete(user)
session.commit()



print("__INFO__ All Done :-) ")
