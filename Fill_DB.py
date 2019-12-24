from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import User, Item, Category, Base

engine = create_engine('sqlite:///Item_Catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

### Adding categories

cat1 = Category(id = 1, name = "Sports")

session.add(cat1)
session.commit()

cat2 = Category(id = 2, name = "Technology")

session.add(cat2)
session.commit()

cat3 = Category(id = 3, name = "Other")

session.add(cat3)
session.commit()

cat4 = Category(id = 4, name = "Science")

session.add(cat4)
session.commit()


print("__INFO__ Categories Added ! ")

### Adding users (authors)

# the used hashing is SHA256

# passcode > Mary@ItemCata321
user1 = User(
          id = 1,
          name = "Mary Hillfiger",
          email = "m.h123@sis.com",
          password_hash = "2cb917e41feba38331cf2b7df8b6f5ea943f4bd65e873a12498748f4ee60ef47",
          picture = "https://picsum.photos/200/300",
          sec_q = "What's your pet's name",
          sec_a = "poppy")

session.add(user1)
session.commit()

# passcode > 12PassCode34@Dunno
user2 = User(
          id = 2,
          name = "Ibraheem Alyan",
          email = "ibraheemalayan@gmail.com",
          password_hash = "274eee5b93f0746611cf725289ddfb5556014650d8991b647482b3fab7397a3b",
          picture = "https://picsum.photos/id/237/200/300",
          sec_q = "Loved port",
          sec_a = "8080")

session.add(user2)
session.commit()

# passcode > SsAaMmIi40.50
user3 = User(
          id = 3,
          name = "Sami Ramadan",
          email = "sami.Rn@twio.edu",
          password_hash = "ff09eb7c5620f1516b41c62b8e9c09c02c606c0d5ae68c0abcfda79f1726d416",
          picture = "https://picsum.photos/200",
          sec_q = "No Qusetion?",
          sec_a = "Just_no_Answer :-)")

session.add(user3)
session.commit()

print("__INFO__ Users Added ! ")

### Adding Items

item1 = Item(
          id = 1,
          title = "Ball",
          description = "A ball is a round object with various uses. It is used in ball games, where the play of the game follows the state of the ball as it is hit, kicked or thrown by players. Balls can also be used for simpler activities, such as catch or juggling.",
          author = user3,
          category = cat1)

session.add(item1)
session.commit()

item2 = Item(
          id = 2,
          title = "Computer",
          description = "A computer is a machine that can be instructed to carry out sequences of arithmetic or logical operations automatically via computer programming. Modern computers have the ability to follow generalized sets of operations, called programs. These programs enable computers to perform an extremely wide range of tasks.",
          author = user2,
          category = cat2)

session.add(item2)
session.commit()

item3 = Item(
          id = 3,
          title = "Paper",
          description = "Paper is a thin material produced by pressing together moist fibres of cellulose pulp derived from wood, rags or grasses, and drying them into flexible sheets. It is a versatile material with many uses, including writing, printing, packaging, cleaning, decorating, and a number of industrial and construction processes.",
          author = user1,
          category = cat3)

session.add(item3)
session.commit()

item4 = Item(
          id = 4,
          title = "Hard Disk",
          description = "A hard disk drive (HDD), hard disk, hard drive, or fixed disk is an electro-mechanical data storage device that uses magnetic storage to store and retrieve digital information using one or more rigid rapidly rotating disks (platters) coated with magnetic material.",
          author = user3,
          category = cat2)

session.add(item4)
session.commit()

item5 = Item(
          id = 5,
          title = "Atom",
          description = "an atom is the smallest component of an element, characterized by a sharing of the chemical properties of the element and a nucleus with neutrons, protons and electrons.",
          author = user2,
          category = cat4)

session.add(item5)
session.commit()

item6 = Item(
          id = 6,
          title = "Application",
          description = "Application software is a program or group of programs designed for end users. Examples of an application include a word processor, a spreadsheet, an accounting application, a web browser, an email client, a media player, a file viewer, an aeronautical flight simulator, a console game or a photo editor.",
          author = user3,
          category = cat2)

session.add(item6)
session.commit()

item7 = Item(
          id = 7,
          title = "Door",
          description = "A door is a hinged or otherwise movable barrier that allows ingress and egress into an \"enclosure\". The opening in the wall can be referred to as a \"portal\". A door's essential and primary purpose is to provide security by controlling the portal (doorway).",
          author = user1,
          category = cat3)

session.add(item7)
session.commit()

item8 = Item(
          id = 8,
          title = "Cricket",
          description = "Cricket is a bat-and-ball game played between two teams of eleven players on a field at the centre of which is a 20-metre pitch with a wicket at each end, each comprising two bails balanced on three stumps.",
          author = user2,
          category = cat1)

session.add(item8)
session.commit()

item9 = Item(
          id = 9,
          title = "Bicycle",
          description = "A bicycle, also called a cycle or bike, is a human-powered or motor-powered, pedal-driven, single-track vehicle, having two wheels attached to a frame, one behind the other. A bicycle rider is called a cyclist, or bicyclist.",
          author = user1,
          category = cat1)

session.add(item9)
session.commit()

item10 = Item(
          id = 10,
          title = "Keyboard",
          description = "A computer keyboard is a typewriter-style device[1] which uses an arrangement of buttons or keys to act as mechanical levers or electronic switches. Following the decline of punch cards and paper tape, interaction via teleprinter-style keyboards became the main input method for computers.",
          author = user2,
          category = cat2)

session.add(item10)
session.commit()

print("__INFO__ Items Added ! ")

### DONE !

print("__INFO__ All Done :-) ")
