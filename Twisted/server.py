from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor


class Chat(LineReceiver):
    def lineReceived(self, line):
        print(line)


class ChatFactory(Factory):
    def buildProtocol(self, addr):
        print(f"Connected to {addr}")
        return Chat()


reactor.listenTCP(8123, ChatFactory())
reactor.run()
