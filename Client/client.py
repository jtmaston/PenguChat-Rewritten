from os import getenv, environ

environ['KIVY_NO_ENV_CONFIG'] = '1'
environ["KCFG_KIVY_LOG_LEVEL"] = "warning"
environ["KCFG_KIVY_LOG_DIR"] = getenv('APPDATA') + '\\PenguChat\\Logs'

from base64 import b64encode
from json import dumps, loads

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.recycleview import RecycleView
from kivy.uix.button import Button

from queue import Queue

from Crypto.Cipher import AES

from kivy.uix.popup import Popup
from kivy import Logger
from kivy.app import App
from kivy.config import Config
from kivy.support import install_twisted_reactor
from pyDHFixed import DiffieHellman

from Client.DBHandler import *

install_twisted_reactor()

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory

Commands = Queue()


class ChatApp(App):
    def __init__(self):
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        self.username = None
        self.destination = None
        self.private = None
        self.factory = None
        self.server_key = None
        self.failed_login = None
        self.failed_signup = None

    """App loading section"""

    def build(self):
        super(ChatApp, self).build()
        self.root.current = 'chat_room'
        task.LoopingCall(self.poll_commands).start(0.5)
        self.factory = ClientFactory()
        reactor.connectTCP("localhost", 8123, self.factory)

    """Server handshake, establish E2E tunnel for password exchange"""

    def secure(self):
        self.private = DiffieHellman()
        public = self.private.gen_public_key()
        command_packet = {
            'command': 'secure',
            'key': public
        }
        self.factory.client.transport.write(dumps(command_packet).encode())

    """Functions that send data to server"""

    def friend_shake(self):
        if not get_key(self.destination):
            public = self.private.gen_public_key()
            command_packet = {
                'command': 'secure_friend',
                'content': public
            }
            self.factory.client.transport.write(dumps(command_packet).encode())

    def send_login_data(self):
        if not self.failed_login:
            pwd = self.root.ids.loginPass.text
            self.username = self.root.ids.loginUsr.text
        else:
            pwd = self.root.ids.loginPass_failed.text
            self.username = self.root.ids.loginUsr_failed.text
        try:
            cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
        except AttributeError:
            self.root.current = 'not_connected_text'
            return 0
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'sender': self.username
        }
        self.root.current = 'loading_screen'
        self.factory.client.transport.write(dumps(login_packet).encode())

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
                'sender': self.username
            }
            self.root.current = 'loading_screen'
            self.factory.client.transport.write(dumps(signup_packet).encode())

    def logout(self):
        self.factory.client.transport.loseConnection()
        self.root.current = 'login'
        self.root.ids.friend_list.data = []

    def send(self):
        message_text = self.root.ids.message_content.text
        self.root.ids.message_content.text = ""
        packet = {
            'sender': self.username,
            'destination': self.destination,
            'command': 'message',
            'content': message_text,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        }
        self.factory.client.transport.write(dumps(packet).encode())

    """Helper functions"""

    def poll_commands(self):
        if not Commands.empty():
            command = Commands.get_nowait()
            if command:
                if command['command'] == 'secure':
                    self.server_key = self.private.gen_shared_key(command['content'])
                elif command['command'] == 'login ok':
                    self.root.current = 'chat_room'
                elif command['command'] == 'signup ok':
                    self.root.current = 'chat_room'
                elif command['command'] == '504':
                    self.root.current = 'not_connected_screen'
                elif command['command'] == '200':
                    self.secure()
                # self.root.current = 'login'
                elif command['command'] == 'friend_key':
                    add_key(command['friend'], self.private.gen_shared_key(command['content']))
                elif command['command'] == 'user exists':
                    self.root.ids.username_fail.text = ""
                    self.root.ids.passwd_fail.text = ""
                    self.root.ids.passwd_r_fail.text = ""
                    self.root.current = 'signup_fail'
                    self.failed_signup = True
                elif command['command'] == 'unauthorized':
                    self.root.current = 'login_failed'
                    self.root.ids.loginPass_failed.text = ""
                    self.root.ids.loginUsr_failed.text = ""
                    self.failed_login = True
                elif command['command'] == 'friend_request':
                    print('here')
                    add_request(command)

    def change_chat_wrapper(self, name):
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

    def hide_friends_list(self):
        wid = self.root.ids.friend_list
        wid.saved_attrs = wid.height, wid.size_hint_y, wid.opacity, wid.disabled
        wid.height, wid.size_hint_y, wid.opacity, wid.disabled = 0, None, 0, True
        self.root.ids.friend_list = wid

    def show_friends_list(self):
        self.root.ids.new_convo_count.text = f"Requests ({len(get_requests(self.username))})"
        self.root.ids.new_convo_count.on_press = self.request_popup
        wid = self.root.ids.friend_list
        try:
            wid.height, wid.size_hint_y, wid.opacity, wid.disabled = wid.saved_attrs
            del wid.saved_attrs
            self.root.ids.message_box = wid
        except AttributeError:
            pass

    def new_chat(self):

        def send_chat_request(text_object):
            add_private_key(text_object.text, self.private.get_private_key())
            packet = {
                'sender': self.username,
                'command': 'friend_request',
                'content': self.private.gen_public_key(),
                'destination': text_box.text,
                'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            }
            self.factory.client.transport.write(dumps(packet).encode())
            popup.dismiss()

        bar = BoxLayout(orientation='horizontal')
        text_box = TextInput(size_hint_x=0.8, write_tab=False, multiline=False)
        text_box.bind(on_text_validate=send_chat_request)
        bar.add_widget(text_box)
        popup = Popup(title='Test popup',
                      content=bar,
                      size_hint=(None, None), size=(800, 400))
        popup.open()

    """Loading functions"""

    def load_friends(self):
        names = get_friends(self.username)
        for i in names:
            self.root.ids.friend_list.data.append(
                {'text': i, 'on_press': self.change_chat_wrapper(i), 'size_hint': (1, None)})

    def load_messages(self):
        messages = ""
        for i in messages:
            self.root.ids.messages.data.append({'text': i, 'color': (0, 0, 0, 1), 'halign': 'left', 'height': 50})

    def load_requests(self):
        self.root.ids.new_convo_count.text = f"Requests ({len(get_requests(self.username))})"

    def request_popup(self):
        requests = get_requests(self.username)
        requests += ['Danny', 'Carl', 'Lewis', 'Dennis', 'Names', 'Someone']
        self.root.ids.new_convo_count.text = "Friend list"
        self.hide_friends_list()
        try:
            if self.switched_menu:
                self.root.ids.new_convo_count.on_press = self.show_friends_list
                del self.switched_menu
        except AttributeError:
            self.switched_menu = True


class Client(Protocol):
    def __init__(self):
        self.username = None
        self.destination = None

    def connectionMade(self):
        Commands.put({'command': "200"})

    def dataReceived(self, data):
        print(data)
        data = data.decode().split('}')
        for i in data:
            if i:
                packet = loads((i + '}').encode())
                if packet['sender'] == 'SERVER':
                    Commands.put(packet)
                else:
                    if packet['command'] == 'message':
                        save_message(packet)
                    else:
                        Commands.put(packet)

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
        Logger.info('Application: Attempting to connect...')

    def clientConnectionFailed(self, connector, reason):
        Commands.put({'command': "504"})
        connector.connect()
        Logger.warning('Application: Connection failed!')

    def clientConnectionLost(self, connector, reason):
        Logger.warning('Application: Connection lost!')
        connector.connect()


if __name__ == '__main__':
    ChatApp().run()
