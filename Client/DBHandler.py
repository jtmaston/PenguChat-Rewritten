# TODO: The database handler needs a redesign


from datetime import datetime
from os import getenv, makedirs

from peewee import *

path = getenv('APPDATA')
path += '\\PenguChat\\DB\\messages.db'

db = SqliteDatabase(path)


class CommonKeys(Model):
    partner_name = CharField(100)
    common_key = BlobField(null=True)
    key_updated = DateTimeField(null=True)

    class Meta:
        database = db


class PrivateKeys(Model):
    partner_name = CharField(100)
    self_private_key = BlobField(null=True)

    class Meta:
        database = db


class Messages(Model):
    sender = CharField(100)
    destination = CharField(100)
    message_text = TextField(100)
    timestamp = DateTimeField()

    class Meta:
        database = db


class Requests(Model):
    sender = CharField(100)
    public_key = BlobField()

    class Meta:
        database = db


def add_key(partner_name, common_key):
    new_key = CommonKeys(partner_name=partner_name, common_key=common_key, key_updated=datetime.now())
    new_key.save()


def add_private_key(partner_name, private_key):
    private_key = str(private_key).encode()
    new_key = PrivateKeys(partner_name=partner_name, self_private_key=private_key)
    new_key.save()


def get_key(partner_name):
    try:
        query = CommonKeys.get(CommonKeys.partner_name == partner_name)
    except CommonKeys.DoesNotExist:
        return False
    else:
        return query.common_key


def get_friends(username):
    query = Messages.select().where((Messages.destination == username) | (Messages.sender == username))
    return list(dict.fromkeys((
            [i.sender for i in query if i.sender != username] +
            [i.destination for i in query if i.destination != username]
    )))


def save_message(message):
    Messages(sender=message['sender'], destination=message['destination'],
             message_text=message['content'], timestamp=datetime.strptime(message['timestamp'], "%m/%d/%Y, "
                                                                                                "%H:%M:%S")).save()


def add_request(packet):
    Requests(sender=packet['sender'], public_key=packet['content']).save()


def get_requests():
    query = Requests.select(Requests.sender)
    return list(dict.fromkeys([i.sender for i in query if i.sender]))


try:
    db.create_tables([CommonKeys, Messages, PrivateKeys, Requests])
except OperationalError as t:
    print(t)
    try:
        makedirs(path)
    except FileExistsError:
        pass
    try:
        open(path)
    except FileNotFoundError:
        with open(path):
            pass
