import builtins

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, Factory, connectionDone
import json
from DatabaseHelper.tools import *

logfile = open('server.log', 'a+')


def log(info):
    logfile.write(info)


class Server(Protocol):
    def __init__(self, factory):
        self.factory = factory
        self.thing = "help"
        self.cache = []

    def connectionMade(self):
        task.LoopingCall(self.clearCache).start(1)

    def connectionLost(self, reason=connectionDone):
        log(datetime.now().strftime("%m/%d/%Y:%H:%M:%S") + " | " + f"Connection closed: {reason}")

    def dataReceived(self, data):
        packet = json.loads(data)
        if packet['command'] != "key":
            print(packet)
        if packet['command'] == 'send' or packet['command'] == 'key':
            try:
                self.factory.connections[packet['username']]
            except KeyError:
                self.factory.connections[packet['username']] = self
            try:
                self.factory.connections[packet['destination']].transport.write(json.dumps(packet).encode())
            except builtins.KeyError:
                self.cache.append(packet)

        if packet['command'] == 'disconnect':
            print(packet['username'] + " disconnected.")
            del self.factory.connections[packet['username']]
            self.transport.loseConnection()

    def clearCache(self):
        for i in self.cache:
            try:
                self.factory.connections[i['destination']].transport.write(json.dumps(i).encode())
            except builtins.KeyError:
                pass
            else:
                self.cache.remove(i)


class ServerFactory(Factory):
    def __init__(self):
        self.connections = dict()

    def buildProtocol(self, addr):
        return Server(self)


if __name__ == '__main__':
    reactor.listenTCP(8123, ServerFactory())
    print("Server started.")
    reactor.run()
