import sqlite3 as sql3
import bcrypt
from peewee import *
from Auth.exceptions import UserNotFoundError, UserExistsError, AuthError



class DBHandler:
    db_name = 'auth.db'

    def __init__(self):
        self.__cursor = None
        self.__db = None
        self.__connect()

    def __run_test(self):
        db = sql3.connect(self.db_name)
        c = db.cursor()
        try:
            c.execute('SELECT * from auth')
        except sql3.OperationalError:
            return 'broken structure', c, db
        return 'ok', c, db

    def __connect(self):
        diagnostic, cursor, database = self.__run_test()
        if diagnostic == 'ok':
            self.__cursor = cursor
            self.__db = database
        elif diagnostic == 'broken structure':
            cursor.execute('CREATE TABLE auth('
                           'id INTEGER PRIMARY KEY, '
                           'username VARCHAR(100), '
                           'hash TEXT, '
                           'salt TEXT)'
                           '')
            self.__cursor = cursor
            self.__db = database

    def create_account(self, username, password):
        user_list = [i[0] for i in self.__cursor.execute('select username from auth').fetchall()]
        if username in user_list:
            raise UserExistsError
        else:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode(), salt)
            self.__cursor.execute(f'INSERT INTO auth (username, hash, salt) VALUES '
                                  f'("{username}", "{hashed.decode()}", "{salt.decode()}");')
            self.__db.commit()

    def authenticate(self, username, password):
        user_list = [i[0] for i in self.__cursor.execute('select username from auth').fetchall()]
        if username not in user_list:
            raise UserNotFoundError
        del user_list
        data = self.__cursor.execute(f'select * from auth where username="{username}"').fetchone()
        salt = data[3].encode()
        test = data[2].encode()
        del data
        password = bcrypt.hashpw(password.encode(), salt)

        if test == password:
            return True
        else:
            raise AuthError

    def delete_account(self, username, password):
        if self.authenticate(username, password):
            self.__cursor.execute(f'DELETE FROM auth WHERE username="{username}"')
            self.__db.commit()

    def change_password(self, username, password, new_password):
        if self.authenticate(username, password):
            salt = bcrypt.gensalt()
            new_password = bcrypt.hashpw(new_password.encode(), salt)
            self.__cursor.execute(f'UPDATE auth '
                                  f'SET '
                                  f'hash = "{new_password.decode()}",'
                                  f'salt = "{salt.decode()}"'
                                  f'WHERE '
                                  f'username = "{username}"')
            self.__db.commit()


if __name__ == '__main__':
    handler = DBHandler()
