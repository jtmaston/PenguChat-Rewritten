from base64 import b64encode
from json import dumps, loads
from os import getenv, environ

environ['KIVY_NO_ENV_CONFIG'] = '1'
environ["KCFG_KIVY_LOG_LEVEL"] = "warning"
environ["KCFG_KIVY_LOG_DIR"] = getenv('APPDATA') + '\\PenguChat\\Logs'
from queue import Queue

from Crypto.Cipher import AES

from kivy import Logger
from kivy.app import App
from kivy.config import Config
from kivy.support import install_twisted_reactor
from pyDHFixed import DiffieHellman

from Client.DBHandler import get_friends

install_twisted_reactor()

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory

Commands = Queue()


class ChatApp(App):
    def get_application_config(self, defaultpath='%(appdir)s/%(appname)s.ini'):
        return super(ChatApp, self).get_application_config(
            getenv('APPDATA') + '\\PenguChat\\Config\\chat.ini')

    def build_config(self, config):
        config.setdefaults('kivy', {
            'log_dir': getenv('APPDATA') + '\\PenguChat\\Logs',
            'log_level': 'warning'
        })

    def build(self):
        super(ChatApp, self).build()
        self.root.current = 'chat_room'
        task.LoopingCall(self.poll_commands).start(0.5)
        self.factory = ClientFactory()
        reactor.connectTCP("localhost", 8123, self.factory)

    def __init__(self):
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        self.username = None
        self.destination = None

    def on_request_close(self, timestamp):
        print(f"Closed at {timestamp}")
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
        try:
            cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
        except AttributeError:
            exit(1)
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'username': self.username
        }
        self.factory.client.transport.write(dumps(login_packet).encode())

    def send(self):
        print(self.destination)

    def poll_commands(self):
        if not Commands.empty():
            command = Commands.get_nowait()
            if command:
                if command['command'] == 'server_key':
                    self.server_key = self.private.gen_shared_key(command['content'])
                elif command['command'] == 'login ok':
                    self.root.current = 'chat_room'
                elif command['command'] == 'signup ok':
                    self.root.current = 'chat_room'
                elif command['command'] == '504':
                    self.root.current = 'error'
                elif command['command'] == '200':
                    self.root.current = 'login'

    def secure(self):
        print("establishing secure channel")
        self.private = DiffieHellman()
        public = self.private.gen_public_key()

        command_packet = {
            'command': 'secure',
            'key': public
        }
        try:
            self.factory.client.transport.write(dumps(command_packet).encode())
        except AttributeError:
            task.deferLater(reactor, 5, self.secure)

    def wrapper(self, name):
        def change_chat(parent=self):
            wid = self.root.ids.message_box
            try:
                wid.height, wid.size_hint_y, wid.opacity, wid.disabled = wid.saved_attrs
                del wid.saved_attrs
                self.root.ids.message_box = wid
                parent.destination = name
            except AttributeError:
                parent.destination = name

        return change_chat

    def hide_message_box(self):
        wid = self.root.ids.message_box
        wid.saved_attrs = wid.height, wid.size_hint_y, wid.opacity, wid.disabled
        wid.height, wid.size_hint_y, wid.opacity, wid.disabled = 0, None, 0, True
        self.root.ids.message_box = wid

    def load_friends(self):
        names = get_friends(self.username)
        for i in names:
            self.root.ids.friend_list.data.append({'text': i, 'on_press': self.wrapper(i), 'size_hint': (1, None)})

    def load_messages(self):
        messages = ['This is a long ass text that should display ok but maybe not']
        messages += [str(i) for i in range(1, 20)]
        for i in messages:
            self.root.ids.messages.data.append({'text': i, 'color': (0, 0, 0, 1), 'halign': 'left'})


class Client(Protocol):
    def __init__(self):
        self.username = None
        self.destination = None

    def connectionMade(self):
        Commands.put({'command': "200"})
        print("Connected!", end="")

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
            elif packet['command'] == 'not found!':
                Commands.put({'command': 'not found!'})

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
        Logger.debug('Application: Attempting to connect...')

    def clientConnectionFailed(self, connector, reason):
        # Commands.put({'command': "504"})
        # connector.connect()
        Logger.warning('Application: Connection failed!')

    def clientConnectionLost(self, connector, reason):
        Logger.warning('Application: Connection lost!')
        connector.connect()


if __name__ == '__main__':
    ChatApp().run()
