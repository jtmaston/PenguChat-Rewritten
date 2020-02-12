from twisted.internet.protocol import *
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor


class Echo(Protocol):
    def dataReceived(self, data):
        self.transport.write(data)


class EchoFactory(Factory):
    def buildProtocol(self, addr):
        return Echo()


endpoint = TCP4ServerEndpoint(reactor, 8080)
endpoint.listen(EchoFactory())
print("Server starting...")
reactor.run()
