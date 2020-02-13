from twisted.internet.protocol import Factory, ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor, task
from queue import Queue
import pyDHFixed as pyDH
commands = Queue()


def kb():
    while True:
        data = input(">")
        commands.put(f":message {data}".encode())


class Sender(LineReceiver):
    def __init__(self, username):
        self.username = username
        self.private = pyDH.DiffieHellman()
        self.public = self.private.gen_public_key()
        self.commandQueue = Queue()
        self.shared = None

    def connectionMade(self):
        self.sendLine(f":handshake {self.public}".encode())
        task.LoopingCall(self.checkQueue).start(0.5)
        task.LoopingCall(self.checkCommands).start(0.5)

    def lineReceived(self, line):
        line = line.decode()
        if line[0] == ':':
            self.commandQueue.put(line[1:].strip())

    def checkQueue(self):
        while not commands.empty():
            self.sendLine(commands.get())

    def checkCommands(self):
        while not self.commandQueue.empty():
            self.execute(self.commandQueue.get_nowait())

    def execute(self, command):
        if command == 'disconnect':
            pass
        elif command[0:7] == 'message':
            print(f"{self.username}: {command[8:]}")
        elif command[0:4] == 'user':
            self.username = command[5:]
        elif command[0:9] == 'handshake':
            partner_public = int(command[10:])
            self.shared = self.private.gen_shared_key(partner_public)
            print("Our shared secret is: ", self.shared)


class SenderFactory(ClientFactory):
    def startedConnecting(self, connector):
        print("Started connecting...")

    def buildProtocol(self, addr):
        return Sender("jamie")

    def clientConnectionFailed(self, connector, reason):
        print(f"Connection failed! Reason: {reason.value}")


if __name__ == '__main__':

    reactor.connectTCP("localhost", 8123, SenderFactory())
    reactor.callInThread(kb)
    reactor.run()

