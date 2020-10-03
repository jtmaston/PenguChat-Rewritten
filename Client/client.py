import builtins
import pickle
import sys

from Client.DBHandler import *
from base64 import b64encode, b64decode
from json import dumps, loads

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.graphics.context_instructions import Color
from kivy.graphics.vertex_instructions import Rectangle
from kivy.uix.popup import Popup
from kivy.app import App
from kivy.config import Config
from kivy.support import install_twisted_reactor
from kivy.base import ExceptionHandler, ExceptionManager

from queue import Queue

from Crypto.Cipher import AES
from pyDH import DiffieHellman

if 'twisted.internet.reactor' in sys.modules:
    del sys.modules['twisted.internet.reactor']
install_twisted_reactor()

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory

Commands = Queue()


class E(ExceptionHandler):
    def handle_exception(self, inst):
        Logger.exception('Application: An exception was encountered')
        return ExceptionManager.PASS


class CustomBoxLayout(BoxLayout):
    def __init__(self, **kwargs):
        super(CustomBoxLayout, self).__init__(**kwargs)
        with self.canvas.before:
            self.color_widget = Color(0.4, 0.4, 0.4, 1)  # red
            self._rectangle = Rectangle()

    def on_size(self, *args):
        if args:
            pass
        self._rectangle.size = self.size
        self._rectangle.pos = self.pos


class SidebarElement:
    def __init__(self, username):
        self.container = CustomBoxLayout(orientation='horizontal')
        self.container.username = username
        self.name = Label(text=username)
        self.accept = Button(text='Accept')
        self.decline = Button(text='Decline')

        self.container.add_widget(self.name)
        self.container.add_widget(self.accept)
        self.container.add_widget(self.decline)


class ConversationElement:

    def __init__(self, text, side):

        class MessageLabel(Label):
            pass

        self.line = BoxLayout(orientation='horizontal')
        self.left = MessageLabel()
        self.right = MessageLabel()
        if side == 'l':
            self.right.text = ""
            self.left.text = text
        else:
            self.right.text = text
            self.left.text = ""

        self.line.add_widget(self.left)
        self.line.add_widget(self.right)


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
        self.sidebar_refs = dict()
        self.conversation_refs = []
        self.friend_refs = []

    """App loading section"""

    def build(self):
        super(ChatApp, self).build()
        self.root.current = 'loading_screen'
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

    """Methods that send data to server"""

    def send_login_data(self):
        if not self.failed_login:
            pwd = self.root.loginPass.text
            self.username = self.root.loginUsr.text
        else:
            pwd = self.root.loginPass_failed.text
            self.username = self.root.loginUsr_failed.text
        try:
            cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
        except AttributeError:
            self.root.current = 'not_connected_text'
            return False
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
        pwd = self.root.passwd.text
        pwd_r = self.root.passwd_r.text
        self.username = self.root.username.text
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
        self.root.current = 'loading_screen'

    def send(self):
        message_text = self.root.message_content.text
        self.root.message_content.text = ""
        cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)
        content = pickle.dumps(cipher.encrypt_and_digest(message_text.encode()))
        content = b64encode(content).decode()
        packet = {
            'sender': self.username,
            'destination': self.destination,
            'command': 'message',
            'content': content,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        }
        save_message(packet, self.username)
        self.load_messages(self.destination)
        self.factory.client.transport.write(dumps(packet).encode())

    """Helper methods"""

    def refresh(self):
        try:
            if self.root.request_button.text[0] == 'F':
                self.set_sidebar_to_request_list()
            elif self.root.request_button.text[0] == 'R':
                self.set_sidebar_to_friend_list()
        except builtins.IndexError:
            pass

    def poll_commands(self):
        if not Commands.empty():
            command = Commands.get_nowait()
            if command:
                if command['command'] == 'secure':
                    self.server_key = self.private.gen_shared_key(command['content'])
                    self.root.current = 'login'
                elif command['command'] == '200':
                    self.root.current = 'chat_room'
                elif command['command'] == '201':
                    self.root.current = 'chat_room'
                elif command['command'] == '504':
                    self.root.current = 'not_connected_screen'
                elif command['command'] == '202':
                    self.secure()
                elif command['command'] == 'friend_key':
                    add_common_key(command['friend'],
                                   self.private.gen_shared_key(command['content']),
                                   self.username)
                elif command['command'] == '406':
                    self.root.username_fail.text = ""
                    self.root.passwd_fail.text = ""
                    self.root.passwd_r_fail.text = ""
                    self.root.current = 'signup_fail'
                    self.failed_signup = True
                elif command['command'] == '401':
                    self.root.current = 'login_failed'
                    self.root.loginPass_failed.text = ""
                    self.root.loginUsr_failed.text = ""
                    self.failed_login = True
                elif command['command'] == 'friend_request':
                    add_request(command)
                    self.refresh()
                elif command['command'] == 'friend_accept':
                    self.accept_request_reply(command)
                elif command['command'] == 'message':
                    save_message(command, self.username)
                    self.load_messages(self.destination)

    def new_chat(self):

        def send_chat_request(text_object):  # save the private key to be used later
            add_private_key(text_object.text, self.private.get_private_key(), self.username)
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
                      size_hint=(None, None),
                      size=(800, 400))
        popup.open()

    def accept_request(self, button_object):
        friend = button_object.parent.username
        friend_key = int(get_key_for_request(self.username, friend).decode())
        common_key = self.private.gen_shared_key(friend_key)
        add_common_key(friend, common_key, self.username)
        self.root.sidebar.remove_widget(button_object.parent)
        delete_request(friend)
        packet = {
            'sender': self.username,
            'command': 'friend_accept',
            'content': self.private.gen_public_key(),
            'destination': friend,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        }
        start_message = {
            'sender': packet['destination'],
            'destination': packet['sender'],
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        }
        save_message(start_message, self.username)
        del self.sidebar_refs[friend]
        self.set_sidebar_to_friend_list()
        self.factory.client.transport.write(dumps(packet).encode())

    def accept_request_reply(self, packet):
        private = DiffieHellman()
        private._DiffieHellman__a = get_private_key(packet['sender'], self.username)  # quick 'n dirty fix
        common = private.gen_shared_key(int(packet['content']))
        add_common_key(packet['sender'], common, self.username)
        delete_private_key(packet['sender'], self.username)
        start_message = {
            'sender': packet['sender'],
            'destination': self.username,
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        }
        save_message(start_message, self.username)
        self.set_sidebar_to_friend_list()

    def deny_request(self, button_object):
        self.root.sidebar.remove_widget(button_object.parent)
        del self.sidebar_refs[button_object.parent.username]
        delete_request(button_object.parent.username)

    """Loading methods"""

    def set_sidebar_to_friend_list(self):
        self.root.sidebar.clear_widgets()
        self.root.request_button.text = f"Requests ({len(get_requests(self.username))})"
        self.root.request_button.on_press = self.set_sidebar_to_request_list

        names = get_friends(self.username)
        self.root.sidebar.clear_widgets()

        for i in names:
            a = Button(text=i)
            a.bind(on_press=self.show_message_box)
            self.root.sidebar.rows += 1
            self.root.sidebar.add_widget(a)
            self.friend_refs.append(a)
        self.root.request_button.canvas.ask_update()

    def set_sidebar_to_request_list(self):
        self.root.sidebar.clear_widgets()
        self.root.request_button.text = "Friends"
        self.root.request_button.on_press = self.set_sidebar_to_friend_list

        requests = get_requests(self.username)
        for i in requests:
            e = SidebarElement(i)
            e.accept.bind(on_press=self.accept_request)
            e.decline.bind(on_press=self.deny_request)
            self.sidebar_refs[i] = e
            self.root.sidebar.rows += 1
            self.root.sidebar.add_widget(e.container)
        self.root.request_button.canvas.ask_update()

    def load_messages(self, partner):
        if len(self.conversation_refs) > 0:
            self.root.conversation.clear_widgets()
            self.conversation_refs.clear()

        messages = get_messages(partner, self.username)

        for i in messages:  # decryption phase
            cipher = AES.new(get_common_key(partner, self.username), AES.MODE_SIV)
            encrypted = pickle.loads(b64decode(i.message_data))
            try:
                i.message_data = cipher.decrypt_and_verify(encrypted[0], encrypted[1]).decode()
            except ValueError:
                Logger.error(f"Application: MAC error on message id {i.id}")
                i.message_data = "[Message decryption failed.]"

        for i in messages:
            if i.sender == self.username:
                e = ConversationElement(text=i.message_data, side='r')
            else:
                e = ConversationElement(text=i.message_data, side='l')
            self.root.conversation.rows += 1
            self.root.conversation.add_widget(e.line)
            self.conversation_refs.append(e)

    def init_chat_room(self):
        self.hide_message_box()
        self.set_sidebar_to_friend_list()
        self.root.conversation.clear_widgets()

    """Widget methods"""

    def show_message_box(self, button_object):
        self.destination = button_object.text
        if self.check_if_hidden(self.root.message_box):
            self.show_widget(self.root.message_box)
        self.load_messages(self.destination)

    def hide_message_box(self):
        self.hide_widget(self.root.message_box)

    """Static methods"""

    def hide_widget(self, widget):
        if not self.check_if_hidden(widget):
            wid = widget
            wid.saved_attrs = wid.height, wid.size_hint_y, wid.opacity, wid.disabled
            wid.height, wid.size_hint_y, wid.opacity, wid.disabled = 0, None, 0, True
            widget = wid
            if widget:
                pass

    def show_widget(self, widget):
        wid = widget
        if self.check_if_hidden(widget):
            wid.height, wid.size_hint_y, wid.opacity, wid.disabled = wid.saved_attrs
            del wid.saved_attrs
            widget = wid
            if widget:
                pass

    @staticmethod
    def check_if_hidden(widget):
        try:
            widget.saved_attrs
        except AttributeError:
            return False
        else:
            return True


class Client(Protocol):
    def __init__(self):
        self.username = None
        self.destination = None

    def connectionMade(self):
        Commands.put({'command': "202"})

    def dataReceived(self, data):
        # print(data)
        data = data.decode().split('}')
        for i in data:
            if i:
                packet = loads((i + '}').encode())
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
        Logger.warning('Application: Connection failed!')
        Commands.put({'command': "504"})
        connector.connect()

    def clientConnectionLost(self, connector, reason):
        Logger.info('Application: Disconnected.')
        connector.connect()


if __name__ == '__main__':
    ExceptionManager.add_handler(E())

    """
    USED FOR BUILDING OF STANDALONE WINDOWS APP
    
    import os
    from kivy.resources import resource_add_path
    
    if hasattr(sys, '_MEIPASS'):
        resource_add_path(os.path.join(sys._MEIPASS))"""

    ChatApp().run()
