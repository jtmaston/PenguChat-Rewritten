from peewee import *
from datetime import datetime

db = SqliteDatabase("/client.db")


class Auth(Model):
    partner_name = CharField(100)
    common_ket = TextField()
    key_updated = DateTimeField()


class Messages(Model):
    sender = CharField(100)
    destination = CharField(100)
    message_text = TextField(100)
    attachments = BlobField(null=True)
    timestamp = DateTimeField()
