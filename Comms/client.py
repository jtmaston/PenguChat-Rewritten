from queue import Queue

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory
from pyDHFixed import DiffieHellman
from Crypto.Cipher import AES
import json

u1 = 'Alexey'
u2 = 'Danny'


class Client(Protocol):
    def __init__(self):
        self.messageQueue = Queue()
        self.private = DiffieHellman()
        self.cipher = None

    def connectionMade(self):
        print("Connected!")
        test = {
            'username': u1,
            'destination': u2,
            'command': 'key',
            'content': self.private.gen_public_key(),
            'tag': None
        }
        self.transport.write(json.dumps(test).encode())
        task.LoopingCall(self.sendMessage).start(0.5)

    def connectionLost(self, reason=connectionDone):
        pass

    def dataReceived(self, data):
        data = json.loads(data)

        if data['command'] == 'send':
            encrypted = data['command']
            tag = data['tag']
            print(encrypted, tag)
            print(f'\r{data["username"]}: {data["content"]}')

        if data['command'] == 'key':
            common = self.private.gen_shared_key(data['content'])
            self.cipher = AES.new(str(common).encode(), AES.MODE_SIV)

    def sendMessage(self):
        if not kbQueue.empty():
            plaintext = kbQueue.get()
            encrypted, tag = self.cipher.encrypt_and_digest(plaintext.encode())
            test = {
                'username': u1,
                'destination': u2,
                'command': 'send',
                'content': encrypted,
                'tag': tag
            }



class ClientFactory(Factory):
    def buildProtocol(self, addr):
        return Client()

    def startedConnecting(self, connector):
        print("Attempting to connect...")

    def clientConnectionFailed(self, connector, reason):
        print("An error occurred.")
        self.stopFactory()

    def clientConnectionLost(self, connector, reason):
        print("An error occurred.")
        self.stopFactory()


kbQueue = Queue()


def kb():
    while True:
        data = input(">")
        kbQueue.put(data)


if __name__ == '__main__':
    reactor.connectTCP("localhost", 8123, ClientFactory())
    reactor.callInThread(kb)
    reactor.run()
