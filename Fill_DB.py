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
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# ## Adding categories

cat1 = Category(id=1, name="Sports")

session.add(cat1)
session.commit()

cat2 = Category(id=2, name="Technology")

session.add(cat2)
session.commit()

cat3 = Category(id=3, name="Other")

session.add(cat3)
session.commit()

cat4 = Category(id=4, name="Science")

session.add(cat4)
session.commit()


print("__INFO__ Categories Added ! ")

# ## Adding users (authors)

# the used hashing is SHA256

# passcode > Mary@ItemCata321
user1 = User(
          id=1,
          name="Mary Hillfiger",
          email="m.h123@sis.com",
          password_hash=(
           "2cb917e41feba38331cf2b7df8b6f5ea943f4bd65e873a12498748f4ee60ef47"),
          picture="https://picsum.photos/200/300",
          sec_q="What's your pet's name",
          sec_a="poppy")

session.add(user1)
session.commit()

# passcode > 12PassCode34@Dunno
user2 = User(
          id=2,
          name="Ibraheem Alyan",
          email="ibraheemalayan@gmail.com",
          password_hash=(
           "274eee5b93f0746611cf725289ddfb5556014650d8991b647482b3fab7397a3b"),
          picture="https://picsum.photos/id/237/200/300",
          sec_q="Loved port",
          sec_a="8080")

session.add(user2)
session.commit()

# passcode > SsAaMmIi40.50
user3 = User(
          id=3,
          name="Sami Ramadan",
          email="sami.Rn@twio.edu",
          password_hash=(
           "ff09eb7c5620f1516b41c62b8e9c09c02c606c0d5ae68c0abcfda79f1726d416"),
          picture="https://picsum.photos/200",
          sec_q="No Qusetion",
          sec_a="Just_no_Answer :-)")

session.add(user3)
session.commit()

print("__INFO__ Users Added ! ")

# ## Adding Items

# to follow pep 8 and to reduce the amount of strings in this file
# I saved the items descriptions in a seperate file

descriptions_file = open('descriptions.txt', 'r')
descs = descriptions_file.read().split("|||")
descriptions_file.close()

# making and adding items

item1 = Item(
          id=1,
          title="Ball",
          description=descs[0],
          author=user3,
          category=cat1)

session.add(item1)
session.commit()

item2 = Item(
          id=2,
          title="Computer",
          description=descs[1],
          author=user2,
          category=cat2)

session.add(item2)
session.commit()

item3 = Item(
          id=3,
          title="Paper",
          description=descs[2],
          author=user1,
          category=cat3)

session.add(item3)
session.commit()

item4 = Item(
          id=4,
          title="Hard Disk",
          description=descs[3],
          author=user3,
          category=cat2)

session.add(item4)
session.commit()

item5 = Item(
          id=5,
          title="Atom",
          description=descs[4],
          author=user2,
          category=cat4)

session.add(item5)
session.commit()

item6 = Item(
          id=6,
          title="Application",
          description=descs[5],
          author=user3,
          category=cat2)

session.add(item6)
session.commit()

item7 = Item(
          id=7,
          title="Door",
          description=descs[6],
          author=user1,
          category=cat3)

session.add(item7)
session.commit()

item8 = Item(
          id=8,
          title="Cricket",
          description=descs[7],
          author=user2,
          category=cat1)

session.add(item8)
session.commit()

item9 = Item(
          id=9,
          title="Bicycle",
          description=descs[8],
          author=user1,
          category=cat1)

session.add(item9)
session.commit()

item10 = Item(
          id=10,
          title="Keyboard",
          description=descs[9],
          author=user2,
          category=cat2)

session.add(item10)
session.commit()

print("__INFO__ Items Added ! ")

# ## DONE !

print("__INFO__ All Done :-) ")
