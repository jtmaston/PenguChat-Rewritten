# TODO: The database handler needs a redesign
from datetime import datetime
from os import makedirs, environ

from appdirs import user_data_dir
from peewee import *

path = user_data_dir("PenguChat")
environ['KIVY_NO_ENV_CONFIG'] = '1'
environ["KCFG_KIVY_LOG_LEVEL"] = "warning"
environ["KCFG_KIVY_LOG_DIR"] = path + '/PenguChat/Logs'
from kivy import Logger
db = SqliteDatabase(path + '/messages.db')


class CommonKeys(Model):
    added_by = CharField(100)  # identifies who added the message to the DB
    partner_name = CharField(100)
    common_key = BlobField(null=True)
    key_updated = DateTimeField(null=True)

    class Meta:
        database = db


class PrivateKeys(Model):
    added_by = CharField(100)  # identifies who added the message to the DB
    partner_name = CharField(100)
    self_private_key = BlobField(null=True)

    class Meta:
        database = db


class Messages(Model):
    added_by = CharField(100)  # identifies who added the message to the DB
    sender = CharField(100)
    destination = CharField(100)
    message_data = BlobField()
    timestamp = DateTimeField()
    isfile = BooleanField()

    class Meta:
        database = db


class Requests(Model):
    sender = CharField(100)
    public_key = BlobField()
    destination = CharField(100)

    class Meta:
        database = db


def add_common_key(partner_name, common_key, added_by):
    try:
        query = CommonKeys.get(CommonKeys.partner_name == partner_name)
    except CommonKeys.DoesNotExist:
        new_key = CommonKeys(
            partner_name=partner_name,
            common_key=common_key,
            key_updated=datetime.now(),
            added_by=added_by
        )
        new_key.save()
    else:
        query.partner_name = partner_name
        query.common_key = common_key
        query.added_by = added_by
        query.key_updated = datetime.now()
        query.save()


def get_common_key(partner_name, username):
    try:
        query = CommonKeys.get(
            (CommonKeys.partner_name == partner_name) &
            (CommonKeys.added_by == username)
        )
    except CommonKeys.DoesNotExist:
        raise DoesNotExist
    else:
        return query.common_key


def add_private_key(partner_name, private_key, username):
    private_key = str(private_key).encode()
    try:
        key = PrivateKeys.get(PrivateKeys.partner_name == partner_name)
    except PrivateKeys.DoesNotExist:
        new_key = PrivateKeys(
            partner_name=partner_name,
            self_private_key=private_key,
            added_by=username
        )
        new_key.save()
    else:
        key.self_private_key = private_key
        key.added_by = username
        key.save()


def get_private_key(partner_name, username):
    try:
        key = PrivateKeys.get(
            (PrivateKeys.partner_name == partner_name) &
            (PrivateKeys.added_by == username)
        )
    except PrivateKeys.DoesNotExist:
        Logger.error("DBHandler: Key not found for user!")
    else:
        return int(key.self_private_key.decode())


def delete_private_key(partner_name, username):
    PrivateKeys.get(
        (PrivateKeys.partner_name == partner_name) &
        (PrivateKeys.added_by == username)
    ).delete_instance()
    db.commit()


def get_friends(username):
    query = Messages.select().where(
        (Messages.destination == username) |
        (Messages.sender == username)
    )
    return list(dict.fromkeys((
            [i.sender for i in query if i.sender != username] +
            [i.destination for i in query if i.destination != username]
    )))


def get_messages(partner, username):
    query = Messages.select().where(
        ((Messages.destination == partner) & (Messages.sender == username)) |
        ((Messages.sender == partner) & (Messages.destination == username))
    ).order_by(Messages.timestamp)
    return [i for i in query if i.message_data.decode() != chr(224) and i.added_by == username and i.isfile == False]


def save_message(packet, username):
    try:
        message = packet['content'].encode()
    except AttributeError:
        message = packet['content']

    Messages(
        sender=packet['sender'],
        destination=packet['destination'],
        message_data=message,
        timestamp=datetime.strptime(packet['timestamp'], "%m/%d/%Y, %H:%M:%S"),
        added_by=username,
        isfile=packet['isfile']
    ).save()


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
    Logger.warning("DBHandler: Creating database file.")
    try:
        makedirs(path)
    except FileExistsError:
        pass
    try:
        open(path)
    except FileNotFoundError:
        with open(path + '/messages.db', 'w+'):
            pass
