from queue import Queue

from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor, task
import pyDHFixed as pyDH


class Chat(LineReceiver):
    def __init__(self, factory):
        self.factory = factory
        self.commandQueue = Queue()
        self.username = None
        self.private = pyDH.DiffieHellman()
        self.public = self.private.gen_public_key()
        self.shared = None

    def connectionMade(self):
        self.factory.clients.add(self)
        self.sendLine(f":handshake {self.public}".encode())
        task.LoopingCall(self.checkCommands).start(0.1)

    def lineReceived(self, line):
        line = line.decode()
        if line[0] == ':':
            self.commandQueue.put(line[1:].strip())

    def checkCommands(self):
        while not self.commandQueue.empty():
            self.execute(self.commandQueue.get_nowait())

    def execute(self, command):
        if command == 'disconnect':
            self.factory.clients.remove(self)
            self.transport.loseConnection()
        elif command[0:7] == 'message':
            print(f"{self.username}: {command[8:]}")
        elif command[0:4] == 'user':
            self.username = command[5:]
        elif command[0:9] == 'handshake':
            partner_public = int(command[10:])
            self.shared = self.private.gen_shared_key(partner_public)
            print("Our shared secret is: ", self.shared)


class ChatFactory(Factory):
    def __init__(self):
        self.clients = set()

    def buildProtocol(self, addr):
        print(f"Connected to {addr}")
        return Chat(self)


if __name__ == '__main__':
    reactor.listenTCP(8123, ChatFactory())
    print("Starting!")
    reactor.run()
