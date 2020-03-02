from datetime import datetime

import bcrypt
from peewee import *

db = SqliteDatabase('D:/pc.db')


class User(Model):
    username = CharField(100)
    password_hash = TextField()
    password_salt = TextField()
    last_login = DateTimeField()

    class Meta:
        database = db


class MessageCache(Model):
    sender = CharField(100)
    destination = CharField(100)
    message_text = TextField()
    timestamp = DateTimeField()
    is_key = BooleanField(default=False)

    class Meta:
        database = db


def add_user(username, pwd, salt):
    try:
        User.get(User.username == username)
    except User.DoesNotExist:
        new_user = User(username=username, password_hash=pwd, password_salt=salt, last_login=datetime.now())
        new_user.save()
        return True
    else:
        return False


def login(username, password):
    try:
        query = User.get(User.username == username)
    except User.DoesNotExist:
        print("notfound")
        return False
    else:
        salt = get_salt_for_user(username)
        password = bcrypt.hashpw(password, salt)
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
        return query.password_salt.encode()
