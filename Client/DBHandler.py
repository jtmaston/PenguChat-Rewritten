from datetime import datetime
from os import getenv, makedirs

from peewee import *

path = getenv('APPDATA')
path += '\\PenguChat\\DB\\messages.db'

db = SqliteDatabase(path)


class Auth(Model):
    partner_name = CharField(100)
    common_key = BlobField()
    key_updated = DateTimeField()

    class Meta:
        database = db


class Messages(Model):
    sender = CharField(100)
    destination = CharField(100)
    message_text = TextField(100)
    timestamp = DateTimeField()

    class Meta:
        database = db


def add_key(partner_name, common_key):
    new_key = Auth(partner_name=partner_name, common_key=common_key, key_updated=datetime.now())
    new_key.save()


def get_key(partner_name):
    try:
        query = Auth.get(Auth.partner_name == partner_name)
    except Auth.DoesNotExist:
        return False
    else:
        return query.common_key


def get_friends(username):
    friend_list = list()
    query = Messages.select(Messages.sender)
    for i in query:
        if i.sender not in friend_list and i.sender != username:
            friend_list.append(i.destination)
    query = Messages.select(Messages.destination)
    for i in query:
        if i.destination not in friend_list and i.destination != username:
            friend_list.append(i.destination)
    friend_list = [i for i in friend_list if i]  # remove empty records
    return friend_list


def save_message(message):
    Messages(sender=message['sender'], destination=message['destination'],
             message_text=message['content'], timestamp=datetime.strptime(message['timestamp'], "%m/%d/%Y, "
                                                                                                "%H:%M:%S")).save()


try:
    db.create_tables([Auth, Messages])
except OperationalError as t:
    try:
        makedirs(path)
    except FileExistsError:
        pass
    try:
        open(path + '\\messages.db')
    except FileNotFoundError:
        with open(path + '\\messages.db', 'w+'):
            pass
