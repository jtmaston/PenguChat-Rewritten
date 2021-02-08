# TODO: The database handler needs a redesign

from datetime import datetime
from os import makedirs, environ

import bcrypt
from appdirs import user_data_dir
from peewee import *

path = user_data_dir("PenguChatServer", "aanas")
environ['KIVY_NO_ENV_CONFIG'] = '1'
environ["KCFG_KIVY_LOG_LEVEL"] = "debug"
environ["KCFG_KIVY_LOG_DIR"] = path + '/PenguChat/Logs'

from kivy import Logger

db = SqliteDatabase(path + '/Users.db')


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
    command = CharField(100)
    content = TextField()
    timestamp = DateTimeField()
    is_key = BooleanField(default=False)
    isfile = BooleanField()

    class Meta:
        database = db


def add_message_to_cache(packet):
    MessageCache(
        sender=packet['sender'],
        destination=packet['destination'],
        content=packet['content'],
        timestamp=packet['timestamp'],
        command=packet['command'],
        isfile=packet['isfile']
    ).save()


def get_cached_messages_for_user(username):
    query = MessageCache.select().where(MessageCache.destination == username)
    messages = []
    for i in query:
        messages.append(i.__data__)
        i.delete_instance()
    db.commit()
    return messages


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
        Logger.warning("User not found!")
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


def get_salt_for_user(username):
    try:
        query = User.get(User.username == username)
    except User.DoesNotExist:
        return False
    else:
        return query.password_salt.encode()


try:
    db.create_tables([User, MessageCache])
except OperationalError as t:
    try:
        makedirs(path)
    except FileExistsError:
        pass
    try:
        open(path + '/Users.db', 'r')
    except FileNotFoundError:
        Logger.warning("Database file missing, re-creating. ")
        with open(path + '/Users.db', "w+"):
            pass
    db.create_tables([User, MessageCache])
