from twisted.internet.protocol import Factory, ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor, task
import threading
from multiprocessing.queues import Queue

commands = Queue()


class KbThread(threading.Thread):
    def run(self) -> None:
        while True:
            data = input(">")
            commands.put(data)


class Sender(LineReceiver):
    def connectionMade(self):
        task.LoopingCall(self.checkQueue()).start(0.5)

    def checkQueue(self):
        print("checking...")
        while not commands.empty():
            self.transport.write(commands.get_nowait())


class SenderFactory(ClientFactory):
    def startedConnecting(self, connector):
        print("")