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
        task.LoopingCall(self.process_command_queue).start(0.5)

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

    def process_command_queue(self):
        if not kbQueue.empty():
            queued_command = kbQueue.get()
            if queued_command['command'] == 'register':
                packet = {
                    'command': 'register',
                    'username': queued_command['args'][0],
                    'password': base64.b64encode(queued_command['args'][1]).decode(),
                    'salt': base64.b64encode(queued_command['args'][2]).decode(),
                    'pfp': base64.b64encode(queued_command['args'][3]).decode()
                }
                self.username = queued_command['args'][0] # vcs
                self.transport.write(json.dumps(packet).encode())
            elif queued_command['command'] == 'send':
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

            elif queued_command['command'] == 'login' and not queued_command['go_around']:
                self.call_for_salt(queued_command['args'][0])
                if not self.salt:
                    print('going around')
                    queued_command['go_around'] = True
                    kbQueue.put(queued_command)
                    return 0
                pwd = bcrypt.hashpw(queued_command['args'][1].encode(), self.salt)
                packet = {
                    'command': 'login',
                    'username': queued_command['args'][0],
                    'password': base64.b64encode(pwd).decode(),
                }
            elif queued_command['command'] == 'login' and queued_command['go_around']:
                if not self.salt:
                    queued_command['go_around'] = True
                    kbQueue.put(queued_command)
                    return 0
                pwd = bcrypt.hashpw(queued_command['args'][1].encode(), self.salt.encode())
                packet = {
                    'command': 'login',
                    'username': queued_command['args'][0],
                    'password': base64.b64encode(pwd).decode(),
                }
                self.transport.write(json.dumps(packet).encode())

    def call_for_salt(self, username):
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
