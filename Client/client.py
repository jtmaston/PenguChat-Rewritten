# os.environ["KIVY_NO_CONSOLELOG"] = "1"

from queue import Queue

from bcrypt import gensalt, hashpw
from kivy.app import App
from kivy.config import Config
from kivy.support import install_twisted_reactor
from kivy.uix.button import Button

install_twisted_reactor()

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory

kbQueue = Queue()


class ChatApp(App):

    def build(self):
        super(ChatApp, self).build()
        self.root.current = 'login'

    def __init__(self):
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        self.factory = ClientFactory()
        reactor.connectTCP("localhost", 8123, self.factory)

    def on_request_close(self, timestamp):
        self.stop()

    def sign_up_redirect(self):
        self.root.current = 'signup'

    def sign_up(self):
        pwd = self.root.ids.passwd.text
        pwd_r = self.root.ids.passwd_r.text
        username = self.root.ids.username.text
        if pwd == pwd_r:
            salt = gensalt()
            pwd = hashpw(pwd.encode(), salt)

    def login(self):
        pwd = self.root.ids.loginPass.text
        username = self.root.ids.loginUsr.text
        self.root.current = 'chatRoom'
        self.load_friends()

    def load_friends(self):
        names = []
        for i in names:
            self.root.ids.messageList.add_widget(Button(text=i, on_press=print))

    def send(self):
        self.factory.client.transport.write("Hello".encode())


class Client(Protocol):
    def __init__(self):
        self.username = None
        self.destination = None

    def connectionMade(self):
        print("\rConnected!\n>", end="")

    def connectionLost(self, reason=connectionDone):
        print(reason.value)


class ClientFactory(Factory):
    def __init__(self):
        self.client = None

    def buildProtocol(self, addr):
        c = Client()
        self.client = c
        return c

    def startedConnecting(self, connector):
        print("Attempting to connect...")

    def clientConnectionFailed(self, connector, reason):
        print("Conn failed.")

    def clientConnectionLost(self, connector, reason):
        print("Conn lost.")


if __name__ == '__main__':
    ChatApp().run()
