import sqlite3 as sql3

from peewee import *

from Auth.exceptions import UserNotFoundError, UserExistsError, AuthError

db = SqliteDatabase('client.db')


class MediaModel(Model):
    name = CharField(100)
    profile_picture = BlobField()

    class Meta:
        database = db


# class MediaHandler:
#     db_name = 'client.db'
#
#     def __init__(self):
#         self.__cursor = None
#         self.__db = None
#         self.__connect()
#
#     def __run_test(self):
#         db = sql3.connect(self.db_name)
#         c = db.cursor()
#         try:
#             c.execute('SELECT * from media')
#         except sql3.OperationalError:
#             return 'broken structure', c, db
#         return 'ok', c, db
#
#     def __connect(self):
#         diagnostic, cursor, database = self.__run_test()
#         if diagnostic == 'ok':
#             self.__cursor = cursor
#             self.__db = database
#         elif diagnostic == 'broken structure':
#             cursor.execute('CREATE TABLE media('
#                            'id INTEGER PRIMARY KEY, '
#                            'username VARCHAR(100), '
#                            'profile_picture BLOB)'
#                            '')
#             self.__cursor = cursor
#             self.__db = database
#
#     def add_picture(self, username, path_to_file):
#         with open(path_to_file, 'rb') as file:
#             blobData = file.read()
#
#         test = self.__cursor.execute(f'select * from media where username = "{username}"').fetchall()
#         if not test:
#             self.__cursor.execute(f'insert into media (username, profile_picture) values ('
#                                   f'"{username}", '
#                                   f'"{blobData}" )')

path = 'C:/Users/aanas/OneDrive/Documents/GitHub/PenguChat-Redesigned/Assets/profile.png'
if __name__ == '__main__':
    db.connect()
    db.create_tables([MediaModel])
    with open(path, 'rb') as file:
        blobData = file.read()
    debug = MediaModel(name='Alexey', profile_picture=blobData)
    debug.save()
    db.commit()
    pass
