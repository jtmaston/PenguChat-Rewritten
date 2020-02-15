import base64
from queue import Queue

import bcrypt
from pyDHFixed import DiffieHellman
from Crypto.Cipher import AES
import json

from kivy.support import install_twisted_reactor

install_twisted_reactor()

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory


class Client(Protocol):
    def __init__(self):
        self.messageQueue = Queue()
        self.private = DiffieHellman()
        self.common = None
        self.username = None
        self.destination = None
        self.salt = None

    def connectionMade(self):
        print("\rConnected!\n>", end="")
        task.LoopingCall(self.processCommandQueue).start(0.5)

    def connectionLost(self, reason=connectionDone):
        pass

    def dataReceived(self, data):
        data = json.loads(data)

        if data['command'] == 'send':
            encrypted = base64.b64decode(data['content'].encode())
            tag = base64.b64decode(data['tag'].encode())
            cipher = AES.new(str(self.common).encode(), AES.MODE_SIV)
            plain = cipher.decrypt_and_verify(encrypted, tag)
            print(f'\r{data["username"]}: {plain.decode()}')

        elif data['command'] == 'key':
            self.common = self.private.gen_shared_key(data['content'])

        elif data['command'] == 'salt':
            self.salt = data['content']

    def processCommandQueue(self):
        if not kbQueue.empty():
            queuedCommand = kbQueue.get()
            if queuedCommand['command'] == 'register':
                packet = {
                    'command': 'register',
                    'username': queuedCommand['args'][0],
                    'password': base64.b64encode(queuedCommand['args'][1]).decode(),
                    'salt': base64.b64encode(queuedCommand['args'][2]).decode(),
                    'pfp': base64.b64encode(queuedCommand['args'][3]).decode()
                }
                self.username = queuedCommand['args'][0] # vcs
                self.transport.write(json.dumps(packet).encode())
            elif queuedCommand['command'] == 'send':
                cipher = AES.new(str(self.common).encode(), AES.MODE_SIV)
                plaintext = kbQueue.get()
                encrypted, tag = cipher.encrypt_and_digest(plaintext.encode())
                packet = {
                    'command': 'send',
                    'username': self.username,
                    'destination': self.destination,
                    'content': base64.b64encode(encrypted).decode(),
                    'tag': base64.b64encode(tag).decode()
                }
                self.transport.write(json.dumps(packet).encode())

            elif queuedCommand['command'] == 'login' and not queuedCommand['go_around']:
                self.callForSalt(queuedCommand['args'][0])
                if not self.salt:
                    print('going around')
                    queuedCommand['go_around'] = True
                    kbQueue.put(queuedCommand)
                    return 0
                pwd = bcrypt.hashpw(queuedCommand['args'][1].encode(), self.salt)
                packet = {
                    'command': 'login',
                    'username': queuedCommand['args'][0],
                    'password': base64.b64encode(pwd).decode(),
                }
            elif queuedCommand['command'] == 'login' and queuedCommand['go_around']:
                if not self.salt:
                    queuedCommand['go_around'] = True
                    kbQueue.put(queuedCommand)
                    return 0
                pwd = bcrypt.hashpw(queuedCommand['args'][1].encode(), self.salt.encode())
                packet = {
                    'command': 'login',
                    'username': queuedCommand['args'][0],
                    'password': base64.b64encode(pwd).decode(),
                }
                self.transport.write(json.dumps(packet).encode())

    def callForSalt(self, username):
        packet = {
            'command': 'salt',
            'username': username,
        }
        self.transport.write(json.dumps(packet).encode())

    def disconnect(self):
        print("Disconnected")
        self.transport.loseConnection()


class ClientFactory(Factory):
    def buildProtocol(self, addr):
        return Client()

    def startedConnecting(self, connector):
        print("Attempting to connect...")

    def clientConnectionFailed(self, connector, reason):
        print("Conn failed.")

    def clientConnectionLost(self, connector, reason):
        print("Conn lost.")


kbQueue = Queue()

if __name__ == '__main__':
    reactor.connectTCP("localhost", 8123, ClientFactory())
    reactor.run()
