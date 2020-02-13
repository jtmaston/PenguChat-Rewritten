from abc import ABC

from twisted.internet.protocol import *
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from twisted.protocols.basic import LineReceiver


class Echo(Protocol):
    def dataReceived(self, data):
        print(data)


class EchoFactory(Factory):
    def buildProtocol(self, addr):
        return Echo()


reactor.listenTCP(8080, EchoFactory())
reactor.run()
#########################################
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.protocol import *
from twisted.internet import reactor
from twisted.protocols.basic import LineReceiver

a = []


class Talker(Protocol):
    def connectionMade(self):
        while True:
            data = input(">")
            self.transport.write(data.encode())
            if data == 'q':
                self.transport.loseConnection()
                break

    def lineReceived(self, line):
        a.append(line)


class TalkerFactory(ClientFactory):
    def startedConnecting(self, connector):
        print("connection starting")

    def buildProtocol(self, addr):
        print(f"connection established to {addr}")
        return Talker()

    def clientConnectionFailed(self, connector, reason):
        print("Connection failed!")
        print(reason)


clientFactory = TalkerFactory()
reactor.connectTCP("localhost", 8080, clientFactory)
reactor.run()
print(a)
