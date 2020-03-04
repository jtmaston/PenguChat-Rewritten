import json
from base64 import b64decode

from Crypto.Cipher import AES
from pyDHFixed import DiffieHellman
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory, connectionDone

from Server.DBHandler import *


def get_transportable_data(packet):
    return json.dumps(packet).encode()


class Server(Protocol):
    def __init__(self, factory):
        self.factory = factory
        self.endpoint_username = None

    def connectionMade(self):
        pass

    def connectionLost(self, reason=connectionDone):
        print(self.endpoint_username + " logged out.")
        del self.factory.connections[self.endpoint_username]
        self.endpoint_username = None

    def dataReceived(self, data):
        packet = json.loads(data)
        print(data)
        if packet['command'] == 'secure':
            private = DiffieHellman()
            public = private.gen_public_key()
            reply = {
                'sender': 'SERVER',
                'command': 'secure',
                'content': public
            }
            self.transport.write(get_transportable_data(reply))
            self.key = private.gen_shared_key(packet['key'])

        elif packet['command'] == 'login':
            cipher = AES.new(self.key.encode(), AES.MODE_SIV)
            encrypted = b64decode(packet['password'].encode())
            tag = b64decode(packet['tag'].encode())
            password = cipher.decrypt_and_verify(encrypted, tag)
            if login(packet['sender'], password):
                print(f"{packet['sender']} logged in.")
                self.factory.connections[packet['sender']] = self
                self.endpoint_username = packet['sender']
                cached = get_cached_messages_for_user(packet['sender'])
                if cached:
                    for i in cached:
                        self.factory.connections[packet['sender']].transport.write(get_transportable_data(i))
                reply = {
                    'sender': 'SERVER',
                    'command': 'login ok'
                }
                self.transport.write(get_transportable_data(reply))
            else:
                reply = {
                    'sender': 'SERVER',
                    'command': 'unauthorized'
                }
                self.transport.write(get_transportable_data(reply))

        elif packet['command'] == 'signup':
            cipher = AES.new(self.key.encode(), AES.MODE_SIV)
            encrypted = b64decode(packet['password'].encode())
            tag = b64decode(packet['tag'].encode())
            password = cipher.decrypt_and_verify(encrypted, tag)
            salt = bcrypt.gensalt()
            password = bcrypt.hashpw(password, salt)
            if add_user(packet['sender'], password, salt):
                reply = {
                    'sender': 'SERVER',
                    'command': 'signup ok'
                }
                self.transport.write(get_transportable_data(reply))
            else:
                reply = {
                    'sender': 'SERVER',
                    'command': 'user exists'
                }
                self.transport.write(get_transportable_data(reply))

        elif packet['command'] == 'message' or packet['command'] == 'friend_request':
            try:
                self.factory.connections[packet['destination']].transport.write(get_transportable_data(packet))
            except KeyError:
                add_message_to_cache(packet)
                reply = {
                    'sender': 'SERVER',
                    'command': 'processed ok'
                }
                self.transport.write(get_transportable_data(reply))


class ServerFactory(Factory):
    def __init__(self):
        self.connections = dict()
        self.mode = None

    def buildProtocol(self, addr):
        return Server(self)


if __name__ == '__main__':
    reactor.listenTCP(8123, ServerFactory())
    print("Server started.")
    reactor.run()
