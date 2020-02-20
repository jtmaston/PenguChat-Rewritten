from os import getenv, makedirs

import peewee
from peewee import *
from datetime import datetime

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
    attachments = BlobField(null=True)
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
