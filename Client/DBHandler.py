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
    message_text = BlobField()
    timestamp = DateTimeField()

    class Meta:
        database = db


class Requests(Model):
    sender = CharField(100)
    public_key = BlobField()
    destination = CharField(100)

    class Meta:
        database = db


def add_common_key(partner_name, common_key):
    try:
        query = CommonKeys.get(CommonKeys.partner_name == partner_name)
    except CommonKeys.DoesNotExist:
        new_key = CommonKeys(partner_name=partner_name, common_key=common_key, key_updated=datetime.now())
        new_key.save()
    else:
        query.partner_name = partner_name
        query.common_key = common_key
        query.key_updated = datetime.now()
        query.save()


def get_common_key(partner_name):
    try:
        query = CommonKeys.get(CommonKeys.partner_name == partner_name)
    except CommonKeys.DoesNotExist:
        raise DoesNotExist
    else:
        return query.common_key


def add_private_key(partner_name, private_key):
    private_key = str(private_key).encode()
    try:
        key = PrivateKeys.get(PrivateKeys.partner_name == partner_name)
    except PrivateKeys.DoesNotExist:
        new_key = PrivateKeys(partner_name=partner_name, self_private_key=private_key)
        new_key.save()
    else:
        key.self_private_key = private_key
        key.save()


def get_private_key(partner_name):
    try:
        key = PrivateKeys.get(PrivateKeys.partner_name == partner_name)
    except PrivateKeys.DoesNotExist:
        return False
    else:
        return int(key.self_private_key.decode())


def delete_private_key(partner_name):
    PrivateKeys.get(PrivateKeys.partner_name == partner_name).delete_instance()
    db.commit()


def get_friends(username):
    query = Messages.select().where((Messages.destination == username) | (Messages.sender == username))
    return list(dict.fromkeys((
            [i.sender for i in query if i.sender != username] +
            [i.destination for i in query if i.destination != username]
    )))


def save_message(packet):
    if type(packet['content']) != 'bytes':
        message = packet['content'].encode()
    else:
        message = packet['content']

    Messages(sender=packet['sender'], destination=packet['destination'],
             message_text=message, timestamp=datetime.strptime(packet['timestamp'], "%m/%d/%Y, "
                                                                                    "%H:%M:%S")).save()


def add_request(packet):
    try:
        key = Requests.get(Requests.sender == packet['sender'])
    except Requests.DoesNotExist:
        Requests(sender=packet['sender'],
                 public_key=str(packet['content']).encode(),
                 destination=packet['destination']).save()


def delete_request(username):
    Requests.get(Requests.sender == username).delete_instance()
    db.commit()


def get_key_for_request(username, sender):
    try:
        key = Requests.get((Requests.sender == sender) & (Requests.destination == username))
        return key.public_key
    except Requests.DoesNotExist:
        return False


def get_requests(username):
    query = Requests.select(Requests.sender).where(Requests.destination == username)
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
