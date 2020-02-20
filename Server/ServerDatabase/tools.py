from peewee import *
import bcrypt
from datetime import datetime

db = SqliteDatabase('D:/pc.db')


class User(Model):
    username = CharField(100)
    password_hash = TextField()
    password_salt = TextField()
    last_login = DateTimeField()
    profile_picture = BlobField()

    class Meta:
        database = db


def add_user(username, pwd, salt, pfp_byte_arr):
    try:
        User.get(User.username == username)
    except User.DoesNotExist:
        new_user = User(username=username, password_hash=pwd, password_salt=salt, last_login=datetime.now(),
                        profile_picture=pfp_byte_arr)
        new_user.save()
    else:
        return False


def login(username, password):
    try:
        query = User.get(User.username == username)
    except User.DoesNotExist:
        print("notfound")
        return False
    else:
        encrypted = query.password_hash.encode()
        if password == encrypted:
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


def create():
    User.create_table()


def get_salt_for_user(username):
    try:
        query = User.get(User.username == username)
    except User.DoesNotExist:
        return False
    else:
        return query.password_salt
