# os.environ["KIVY_NO_CONSOLELOG"] = "1"

import base64
import json
from queue import Queue

import bcrypt
from Crypto.Cipher import AES
from kivy.app import App
from kivy.config import Config
from kivy.support import install_twisted_reactor
from kivy.uix.button import Button
from pyDHFixed import DiffieHellman

from ClientDatabase.tools import add_key, get_key

install_twisted_reactor()

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory

kbQueue = Queue()


class ChatApp(App):
    def build(self):
        super(ChatApp, self).build()
        self.root.current = 'login'

    def __init__(self):
        """Set login page size and screen"""
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        Config.write()

    def on_request_close(self, timestamp):
        reactor.stop()
        self.stop()

    def sign_up_redirect(self):
        self.root.current = 'signup'

    def sign_up(self):
        pwd = self.root.ids.passwd.text
        pwd_r = self.root.ids.passwd_r.text
        username = self.root.ids.username.text
        if pwd == pwd_r:
            salt = bcrypt.gensalt()
            pwd = bcrypt.hashpw(pwd.encode(), salt)
            command = {'command': 'register', 'args': (username, pwd, salt)}
            reactor.connectTCP("localhost", 8123, ClientFactory())
            kbQueue.put(command)

    def login(self):
        pwd = self.root.ids.loginPass.text
        username = self.root.ids.loginUsr.text
        command = {'command': 'login', 'args': (username, pwd)}
        reactor.connectTCP("localhost", 8123, ClientFactory())
        kbQueue.put(command)
        self.root.current = 'chatRoom'
        self.load_friends()

    def load_friends(self):
        names = ['Alex', 'Jay', 'Marc']
        for i in names:
            self.root.ids.messageList.add_widget(Button(text=i, on_press=print))


class Client(Protocol):
    def __init__(self):
        self.messageQueue = Queue()
        self.private = DiffieHellman()
        self.common = None
        self.username = "Dave"
        self.destination = 'Danny'
        self.salt = None

    def connectionMade(self):
        print("\rConnected!\n>", end="")
        key = get_key(self.destination)
        if key:
            self.common = key
        else:
            pass
        self.process_command_queue()

    def connectionLost(self, reason=connectionDone):
        print(reason.value)

    def dataReceived(self, data):
        data = json.loads(data)

        if data['command'] == 'send':
            encrypted = base64.b64decode(data['content'].encode())
            tag = base64.b64decode(data['tag'].encode())
            cipher = AES.new(str(self.common).encode(), AES.MODE_SIV)
            plain = cipher.decrypt_and_verify(encrypted, tag)
            print(f'\r{data["username"]}: {plain.decode()}')

        elif data['command'] == 'key':
            self.common = self.private.gen_shared_key(data['content'])
            add_key(self.destination, self.common)

        elif data['command'] == 'salt':
            self.salt = data['content']

        elif data['command'] == 'login OK':
            task.LoopingCall(self.process_command_queue).start(0.5)

    def process_command_queue(self):
        if not kbQueue.empty():
            queued_command = kbQueue.get()
            if queued_command['command'] == 'register':
                packet = {
                    'command': 'register',
                    'username': queued_command['args'][0],
                    'password': base64.b64encode(queued_command['args'][1]).decode(),
                    'salt': base64.b64encode(queued_command['args'][2]).decode(),
                    'pfp': base64.b64encode(queued_command['args'][3]).decode()
                }
                self.username = queued_command['args'][0]  # vcs
                self.transport.write(json.dumps(packet).encode())
            elif queued_command['command'] == 'send':
                cipher = AES.new(str(self.common).encode(), AES.MODE_SIV)
                plaintext = kbQueue.get()
                encrypted, tag = cipher.encrypt_and_digest(plaintext.encode())
                packet = {
                    'command': 'send',
                    'username': self.username,
                    'destination': self.destination,
                    'content': base64.b64encode(encrypted).decode(),
                    'tag': base64.b64encode(tag).decode()
                }
                self.transport.write(json.dumps(packet).encode())

            elif queued_command['command'] == 'login':
                if self.common:
                    self.call_for_salt(queued_command['args'][0])
                    if not self.salt:
                        print('going round')
                        kbQueue.put(queued_command)
                        return 0
                    pwd = bcrypt.hashpw(queued_command['args'][1].encode(), self.salt.encode())
                    packet = {
                        'command': 'login',
                        'username': queued_command['args'][0],
                        'password': base64.b64encode(pwd).decode(),
                    }
                    self.transport.write(json.dumps(packet).encode())
                else:
                    kbQueue.put(queued_command)

    def call_for_salt(self, username):
        packet = {
            'command': 'salt',
            'username': username,
        }
        self.transport.write(json.dumps(packet).encode())

    def disconnect(self):
        print("Disconnected")
        self.transport.loseConnection()


class ClientFactory(Factory):
    def buildProtocol(self, addr):
        return Client()

    def startedConnecting(self, connector):
        print("Attempting to connect...")

    def clientConnectionFailed(self, connector, reason):
        print("Conn failed.")

    def clientConnectionLost(self, connector, reason):
        print("Conn lost.")


if __name__ == '__main__':
    ChatApp().run()
