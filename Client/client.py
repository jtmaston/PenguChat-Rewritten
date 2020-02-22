# os.environ["KIVY_NO_CONSOLELOG"] = "1"
from base64 import b64encode
from json import dumps, loads
from queue import Queue

from Crypto.Cipher import AES
from kivy.app import App
from kivy.config import Config
from kivy.support import install_twisted_reactor
from kivy.uix.button import Button
from pyDHFixed import DiffieHellman

install_twisted_reactor()

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory

Commands = Queue()


class ChatApp(App):

    def build(self):
        super(ChatApp, self).build()
        self.root.current = 'login'
        task.LoopingCall(self.poll_commands).start(0.5)

    def __init__(self):
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')

        self.factory = ClientFactory()
        reactor.connectTCP("localhost", 8123, self.factory)
        """Establish a secure connection"""
        self.username = None

    def on_request_close(self, timestamp):
        self.stop()

    def sign_up_redirect(self):
        self.root.current = 'signup'

    def send_sign_up_data(self):
        pwd = self.root.ids.passwd.text
        pwd_r = self.root.ids.passwd_r.text
        self.username = self.root.ids.username.text
        if pwd == pwd_r:
            cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
            encrypted, tag = cipher.encrypt_and_digest(pwd.encode())

            signup_packet = {
                'command': 'signup',
                'password': b64encode(encrypted).decode(),
                'tag': b64encode(tag).decode(),
                'username': self.username
            }
            self.factory.client.transport.write(dumps(signup_packet).encode())

    def send_login_data(self):

        pwd = self.root.ids.loginPass.text
        self.username = self.root.ids.loginUsr.text
        cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'username': self.username
        }
        self.factory.client.transport.write(dumps(login_packet).encode())

    def load_friends(self):
        names = []
        for i in names:
            self.root.ids.messageList.add_widget(Button(text=i, on_press=print))

    def send(self):
        self.factory.client.transport.write("Hello".encode())

    def poll_commands(self):
        if not Commands.empty():
            command = Commands.get_nowait()
            if command:
                if command['command'] == 'server_key':
                    self.server_key = self.private.gen_shared_key(command['content'])
                elif command['command'] == 'login ok':
                    self.load_friends()
                    self.root.current = 'chat_room'
                elif command['command'] == 'signup ok':
                    self.load_friends()
                    self.root.current = 'chat_room'

    def secure(self):
        print("establishing secure channel")
        self.private = DiffieHellman()
        public = self.private.gen_public_key()

        command_packet = {
            'command': 'secure',
            'key': public
        }
        self.factory.client.transport.write(dumps(command_packet).encode())


class Client(Protocol):
    def __init__(self):
        self.username = None
        self.destination = None

    def connectionMade(self):
        print("\rConnected!\n>", end="")

    def dataReceived(self, data):
        print(data)
        packet = loads(data)

        if packet['username'] == 'SERVER':
            if packet['command'] == 'secure':
                Commands.put({'command': 'server_key', 'content': packet['key']})
            elif packet['command'] == 'login ok':
                Commands.put({'command': 'login ok'})
            elif packet['command'] == 'signup ok':
                Commands.put({'command': 'signup ok'})

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
        print("Conn lost. Attempting a reconnect.")
        connector.connect()


if __name__ == '__main__':
    ChatApp().run()
