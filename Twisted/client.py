from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.protocol import *
from twisted.internet import reactor


class Talker(Protocol):
    def connectionMade(self):
        while True:
            data = input(">")
            if data == '/stop':
                self.transport.loseConnection()
            else:
                self.transport.write(data)

    def dataReceived(self, data):
        print("Got data from server:", data)


endpoint = TCP4ClientEndpoint(reactor, "localhost", 8080)
