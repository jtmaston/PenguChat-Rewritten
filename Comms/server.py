import builtins
from base64 import b64decode

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, Factory, connectionDone
import json
from ServerDatabase.tools import *

logfile = open('server.log', 'w+')


def log(info):
    logfile.write(info)


class Server(Protocol):
    def __init__(self, factory):
        self.factory = factory
        self.cache = []

    def connectionMade(self):
        task.LoopingCall(self.clear_cache).start(1)

    def connectionLost(self, reason=connectionDone):
        log(datetime.now().strftime("%m/%d/%Y:%H:%M:%S") + " | " + f"Connection closed: {reason}")

    def dataReceived(self, data):
        packet = json.loads(data)
        print(packet)
        if packet['command'] == 'send' or packet['command'] == 'key':
            try:
                self.factory.connections[packet['destination']].transport.write(json.dumps(packet).encode())
            except builtins.KeyError:
                self.cache.append(packet)

        elif packet['command'] == 'disconnect':
            print(packet['username'] + " disconnected.")
            del self.factory.connections[packet['username']]
            self.transport.loseConnection()

        elif packet['command'] == 'register':
            password = b64decode(packet['password'])
            salt = b64decode(packet['salt'])
            pfp = b64decode(packet['pfp'])
            add_user(packet['username'], password, salt, pfp)

        elif packet['command'] == 'salt':
            salt = get_salt_for_user(packet['username'])
            if salt:
                packet = {
                    'command': 'salt',
                    'username': packet['username'],
                    'content': salt
                }
                self.transport.write(json.dumps(packet).encode())

        elif packet['command'] == 'login':
            if login(packet['username'], b64decode(packet['password'].encode())):
                try:
                    self.factory.connections[packet['username']]
                except KeyError:
                    self.factory.connections[packet['username']] = self
                else:
                    log(f"{packet['username']}: Disconnected")
                    self.factory.connections[packet['username']].transport.loseConnection()
                    self.factory.connections[packet['username']] = self
                log(f"{packet['username']}: Connected")

    def clear_cache(self):
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
        self.mode = None

    def buildProtocol(self, addr):
        return Server(self)


if __name__ == '__main__':
    reactor.listenTCP(8123, ServerFactory())
    create()
    print("Server started.")
    reactor.run()
