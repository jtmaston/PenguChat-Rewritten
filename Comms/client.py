import base64
from queue import Queue

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory
from pyDHFixed import DiffieHellman
from Crypto.Cipher import AES
import json


class Client(Protocol):
    def __init__(self, username, destination):
        self.messageQueue = Queue()
        self.private = DiffieHellman()
        self.common = None
        self.username = username
        self.destination = destination

    def connectionMade(self):
        print("\rConnected!\n>", end="")
        test = {
            'username': self.username,
            'destination': self.destination,
            'command': 'key',
            'content': self.private.gen_public_key(),
            'tag': None
        }
        self.transport.write(json.dumps(test).encode())
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

        if data['command'] == 'key':
            self.common = self.private.gen_shared_key(data['content'])

    def processCommandQueue(self):
        if not kbQueue.empty():
            queuedCommand = kbQueue.get()
            if queuedCommand:
                pass
        # cipher = AES.new(str(self.common).encode(), AES.MODE_SIV)
        # plaintext = kbQueue.get()
        # encrypted, tag = cipher.encrypt_and_digest(plaintext.encode())
        # packet = {
        #     'username': self.username,
        #     'destination': self.destination,
        #     'command': 'send',
        #     'content': base64.b64encode(encrypted).decode(),
        #     'tag': base64.b64encode(tag).decode()
        # }
        # self.transport.write(json.dumps(packet).encode())

    def disconnect(self):
        print("Disconnected")
        self.transport.loseConnection()


class ClientFactory(Factory):
    def buildProtocol(self, addr):
        return Client("Alexey", "Alexey")

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
