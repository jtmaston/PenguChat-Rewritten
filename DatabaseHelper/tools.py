from peewee import *
import bcrypt
from datetime import datetime

db = SqliteDatabase('C:/Users/aanas/Desktop/pc.db')


class User(Model):
    username = CharField(100)
    password_hash = TextField()
    password_salt = TextField()
    last_login = DateTimeField()
    profile_picture = BlobField()

    class Meta:
        database = db


def add_user(username, password, pfp_source):
    salt = bcrypt.gensalt()
    pwd = bcrypt.hashpw(password.encode(), salt)
    with open(pfp_source, 'rb') as file:
        image_bin = file.read()
    new_user = User(username=username, password_hash=pwd, password_salt=salt, last_login=datetime.now(),
                    profile_picture=image_bin)
    new_user.save()


def login(username, password):
    try:
        query = User.get(User.username == username)
    except User.DoesNotExist:
        return False
    else:
        encrypted = query.password_hash.encode()
        salt = query.password_salt.encode()
        if bcrypt.hashpw(password.encode(), salt) == encrypted:
            query.last_login = datetime.now()
            query.save()
            return True
        else:
            return False


def delete_user(username, password):
    if login(username, password):
        User.delete().where(User.username == username).execute()
        return True
    return False


if __name__ == '__main__':
    pass
