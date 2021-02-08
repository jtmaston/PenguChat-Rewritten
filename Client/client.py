import builtins
import os
import pickle
from base64 import b64encode, b64decode
from json import dumps, loads
from queue import Queue
import sys

from Crypto.Cipher import AES
from kivy.app import App
from kivy.base import ExceptionHandler, ExceptionManager
from kivy.clock import Clock
from kivy.config import Config
from kivy.graphics.context_instructions import Color
from kivy.graphics.vertex_instructions import Rectangle
from kivy.properties import ObjectProperty
from kivy.support import install_twisted_reactor
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from pyDH import DiffieHellman

from Client.DBHandler import *

if 'twisted.internet.reactor' in sys.modules:
    del sys.modules['twisted.internet.reactor']
install_twisted_reactor()

from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory

class MessageLabelLeft(Label):
    pass


class MessageLabelRight(Label):
    pass


class MenuButton(Button):
    pass


class BackgroundContainer(BoxLayout):
    pass


class EmptyWidget(Widget):
    pass


class ColoredLabel(Label):
    def __init__(self, color='gray', **kwargs):
        super(ColoredLabel, self).__init__(**kwargs)

        colors = {
            'red': (1, 0, 0),
            'gray': (0.4, 0.4, 0.4),
            'menu_blue': (0, 0.413, 0.586),
            'menu_light_blue': (0.096, 0.535, 0.656)
        }

        with self.canvas.before:
            self.background_color = Color()
            self.background_color.rgb = colors[color]
            self.rect = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, value, new_position):
        self.rect.pos = self.pos
        self.rect.size = self.size


class SidebarElement:
    def __init__(self, username):
        self.container = BoxLayout(orientation='horizontal')
        self.container.username = username
        self.yes_no_container = BoxLayout(orientation='vertical')

        self.name = ColoredLabel(text=username, color='menu_light_blue')

        self.accept = MenuButton(text='Accept')
        self.decline = MenuButton(text='Decline')
        self.yes_no_container.add_widget(self.accept)
        self.yes_no_container.add_widget(self.decline)
        self.container.add_widget(self.name)
        self.container.add_widget(self.yes_no_container)
        self.name.size_hint_x = 0.6
        self.yes_no_container.size_hint_x = 0.4


class ExceptionWatchdog(ExceptionHandler):
    def handle_exception(self, inst):
        if type(inst) == KeyboardInterrupt:
            exit(0)
        else:
            Logger.exception('An error has occurred.')
            exit(1)

        return ExceptionManager.PASS


class ConversationElement:

    def __init__(self, text, side):

        self.line = BoxLayout(orientation='horizontal')
        self.left = None
        self.right = None

        if side == 'l':
            self.left = MessageLabelLeft(text=text)
            self.right = EmptyWidget()
        else:
            self.right = MessageLabelRight(text=text)
            self.left = EmptyWidget()

        self.line.add_widget(self.left)
        self.line.add_widget(self.right)


class FileDialog(FloatLayout):
    load = ObjectProperty(None)
    cancel = ObjectProperty(None)


class ChatApp(App):
    _popup: Popup

    def __init__(self):
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        self.username = None
        self.destination = None
        self.private = None
        self.factory = None
        self.server_key = None
        self.sidebar_refs = dict()
        self.conversation_refs = []
        self.friend_refs = []

    """App loading section"""

    def build(self):
        super(ChatApp, self).build()
        self.root.current = 'loading_screen'
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
        pwd = self.root.ids.loginPass.text
        self.username = self.root.ids.loginUsr.text
        try:
            cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
        except AttributeError:
            self.factory.client.transport.loseConnection()
            self.fail_connection()
            return False
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'sender': self.username,
            'isfile': False
        }
        self.root.current = 'loading_screen'
        self.factory.client.transport.write(dumps(login_packet).encode())

    def send_sign_up_data(self):
        pwd = self.root.ids.passwd.text
        pwd_r = self.root.ids.passwd_r.text
        self.username = self.root.ids.username.text

        self.pwd = pwd

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
        message_text = self.root.ids.message_content.text
        self.root.ids.message_content.text = ""
        cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)
        content = pickle.dumps(cipher.encrypt_and_digest(message_text.encode()))
        content = b64encode(content).decode()
        packet = {
            'sender': self.username,
            'destination': self.destination,
            'command': 'message',
            'content': content,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        save_message(packet, self.username)
        self.factory.client.transport.write(dumps(packet).encode())
        self.load_messages(self.destination)

    def send_file(self, stream, filename):
        cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)
        content = pickle.dumps(cipher.encrypt_and_digest(stream))
        content = b64encode(content).decode()
        cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)
        filename = pickle.dumps(cipher.encrypt_and_digest(filename.encode()))
        filename = b64encode(filename).decode()
        packet = {
            'sender': self.username,
            'destination': self.destination,
            'command': 'message',
            'content': dumps(
                {'filename': filename, 'file_contents': content}  # Done: filename needs encryption, too!
            ),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': True
        }
        save_message(packet, self.username)
        self.factory.client.transport.write(dumps(packet).encode())
        self.load_messages(self.destination)

    def attach_file(self):
        def dismiss_popup():
            self._popup.dismiss()

        content = FileDialog(load=self.load_file, cancel=dismiss_popup)
        self._popup = Popup(title="Load file", content=content,
                            size_hint=(0.9, 0.9))
        self._popup.open()

    """Helper methods"""

    def refresh(self):
        try:
            if self.root.ids.request_button.text[0] == 'F':
                self.set_sidebar_to_request_list()
            elif self.root.ids.request_button.text[0] == 'R':
                self.set_sidebar_to_friend_list()
        except builtins.IndexError:
            pass

    def load_file(self, filepath, full_path):
        file = open(full_path[0], "rb")
        self.send_file(file.read(), os.path.basename(file.name))
        self._popup.dismiss()

    def secure_server(self, command):
        self.server_key = self.private.gen_shared_key(command['content'])
        self.root.current = 'login'

    def login_ok(self, command):
        for screen in self.root.screens:
            if screen.name == 'login':
                try:
                    screen.has_error
                except AttributeError:
                    pass
                else:
                    if screen.has_error:
                        screen.has_error = False
                        screen.children[0].remove_widget(screen.children[0].children[
                                                             len(screen.children[0].children) - 1])

        self.root.current = 'chat_room'

    def signup_ok(self, command):
        for screen in self.root.screens:
            if screen.name == 'signup':
                try:
                    screen.has_error
                except AttributeError:
                    pass
                else:
                    if screen.has_error:
                        screen.has_error = False
                        screen.children[0].remove_widget(screen.children[0].children[
                                                             len(screen.children[0].children) - 1])
                screen.has_error = False

        pwd = self.pwd
        try:
            cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
        except AttributeError:
            self.factory.client.transport.loseConnection()
            self.fail_connection()
            return False
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'sender': self.username,
            'isfile': False
        }
        self.root.current = 'loading_screen'
        Clock.usleep(50000)
        self.factory.client.transport.write(dumps(login_packet).encode())

    def got_friend_key(self, command):
        add_common_key(command['friend'],
                       self.private.gen_shared_key(command['content']),
                       self.username)

    def username_taken(self, command):
        for screen in self.root.screens:
            if screen.name == 'signup':
                try:
                    screen.has_error
                except AttributeError:
                    screen.has_error = False
                finally:
                    if not screen.has_error:
                        error = ColoredLabel(color='red')
                        error.size_hint_y = 0.2
                        error.text = "Username is taken, sorry!"
                        screen.children[0].add_widget(error, len(screen.children[0].children))
                        screen.has_error = True

        self.root.current = 'signup'

    def login_failed(self, command):
        for screen in self.root.screens:
            if screen.name == 'login':
                try:
                    screen.has_error
                except AttributeError:
                    screen.has_error = False
                finally:
                    if not screen.has_error:
                        error = ColoredLabel(color='red')
                        error.size_hint_y = 0.2
                        error.text = "Username or password incorrect."
                        screen.children[0].add_widget(error, len(screen.children[0].children))
                        screen.has_error = True

        self.root.current = 'login'

    def new_chat(self):

        def send_chat_request(text_object):  # save the private key to be used later
            add_private_key(text_box.text, self.private.get_private_key(), self.username)
            packet = {
                'sender': self.username,
                'command': 'friend_request',
                'content': self.private.gen_public_key(),
                'destination': text_box.text,
                'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                'isfile': False
            }
            self.factory.client.transport.write(dumps(packet).encode())
            popup.dismiss()

        container = BackgroundContainer(orientation='vertical', padding=10, spacing=10)

        popup = Popup(title='Send friend request',
                      content=container,
                      size_hint=(None, None),
                      size=(400, 300))

        text_box = TextInput(write_tab=False, multiline=False, size_hint_y=0.6)
        button_box = BoxLayout(orientation='horizontal', size_hint_y=0.4, padding=10, spacing=10)

        text_box.bind(on_text_validate=send_chat_request)
        button_send = MenuButton(text="Send!", on_press=send_chat_request)
        button_cancel = MenuButton(text="Cancel", on_press=popup.dismiss)

        container.add_widget(text_box)
        button_box.add_widget(button_send)
        button_box.add_widget(button_cancel)
        container.add_widget(button_box)

        popup.open()

    def accept_request(self, button_object):
        friend = button_object.parent.parent.username  # Must move up two boxes, first parent is ver box second is hor
        friend_key = int(get_key_for_request(self.username, friend).decode())
        common_key = self.private.gen_shared_key(friend_key)
        add_common_key(friend, common_key, self.username)
        self.root.ids.sidebar.remove_widget(button_object.parent)
        delete_request(friend)
        packet = {
            'sender': self.username,
            'command': 'friend_accept',
            'content': self.private.gen_public_key(),
            'destination': friend,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        start_message = {
            'sender': packet['destination'],
            'destination': packet['sender'],
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        save_message(start_message, self.username)
        del self.sidebar_refs[friend]
        self.set_sidebar_to_friend_list()
        self.factory.client.transport.write(dumps(packet).encode())

    def accept_request_reply(self, packet):
        private = DiffieHellman()
        private._DiffieHellman__a = get_private_key(packet['sender'], self.username)  # quick 'n dirty fix. should be
        common = private.gen_shared_key(int(packet['content']))  # TODO: Sometimes getting errors. Why?
        add_common_key(packet['sender'], common, self.username)
        delete_private_key(packet['sender'], self.username)
        start_message = {
            'sender': packet['sender'],
            'destination': self.username,
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        save_message(start_message, self.username)
        self.set_sidebar_to_friend_list()

    def deny_request(self, button_object):
        self.root.ids.sidebar.remove_widget(button_object.parent)
        del self.sidebar_refs[button_object.parent.parent.username]
        delete_request(button_object.parent.parent.username)

    """Loading methods"""

    def set_sidebar_to_friend_list(self):
        self.root.ids.sidebar.clear_widgets()
        self.root.ids.request_button.text = f"Requests ({len(get_requests(self.username))})"
        self.root.ids.request_button.on_press = self.set_sidebar_to_request_list

        names = get_friends(self.username)
        self.root.ids.sidebar.clear_widgets()

        for i in names:
            a = MenuButton(text=i)
            a.bind(on_press=self.show_message_box)
            self.root.ids.sidebar.rows += 1
            self.root.ids.sidebar.add_widget(a)
            self.friend_refs.append(a)
        self.root.ids.request_button.canvas.ask_update()

    def set_sidebar_to_request_list(self):
        self.root.ids.sidebar.clear_widgets()
        self.root.ids.request_button.text = "Friends"
        self.root.ids.request_button.on_press = self.set_sidebar_to_friend_list

        requests = get_requests(self.username)
        for i in requests:
            e = SidebarElement(i)

            e.accept.bind(on_press=self.accept_request)
            e.decline.bind(on_press=self.deny_request)
            self.sidebar_refs[i] = e
            self.root.ids.sidebar.rows += 1
            self.root.ids.sidebar.add_widget(e.container)
        self.root.ids.request_button.canvas.ask_update()

    def load_messages(self, partner):
        if len(self.conversation_refs) > 0:
            self.root.ids.conversation.clear_widgets()
            self.conversation_refs.clear()

        messages = get_messages(partner, self.username)

        for i in messages:  # decryption phase
            cipher = AES.new(get_common_key(partner, self.username), AES.MODE_SIV)
            encrypted = pickle.loads(b64decode(i.message_data))
            try:
                i.message_data = cipher.decrypt_and_verify(encrypted[0], encrypted[1]).decode()
            except ValueError:
                Logger.error(f"Application: MAC error on message id {i.id}")
                i.message_data = "[Message decryption failed.]"  # note: maybe change to something less scary for the
                pass  # user?

        for i in messages:
            if i.sender == self.username:
                e = ConversationElement(text=i.message_data, side='r')
            else:
                e = ConversationElement(text=i.message_data, side='l')
            self.root.ids.conversation.rows += 1
            self.root.ids.conversation.add_widget(e.line)

            self.conversation_refs.append(e)

    def init_chat_room(self):
        self.hide_message_box()
        self.set_sidebar_to_friend_list()
        self.root.ids.conversation.clear_widgets()

    """Widget methods"""

    def show_message_box(self, button_object):
        self.destination = button_object.text
        self.root.ids.message_box.foreground_color = (0, 0, 0)
        if self.check_if_hidden(self.root.ids.message_box):
            self.show_widget(self.root.ids.message_box)
        self.load_messages(self.destination)

    def hide_message_box(self):
        self.hide_widget(self.root.ids.message_box)

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

    """Static methods"""

    @staticmethod
    def check_if_hidden(widget):
        try:
            widget.saved_attrs
        except AttributeError:
            return False
        else:
            return True

    def fail_connection(self):
        for screen in self.root.screens:
            if screen.name == 'login':
                try:
                    screen.network_error
                except AttributeError:
                    error = ColoredLabel(color='red')
                    error.size_hint_y = 0.2
                    error.text = "Cannot connect!"
                    for i in screen.children[0].children:
                        i.disabled = True
                    screen.children[0].add_widget(error, len(screen.children[0].children))
                    screen.network_error = True
        self.root.current = 'login'

    def succeed_connection(self):
        for screen in self.root.screens:
            if screen.name == 'login':
                try:
                    screen.network_error
                except AttributeError:
                    pass
                else:
                    if screen.network_error:
                        screen.network_error = False
                        screen.children[0].remove_widget(screen.children[0].children[
                                                             len(screen.children[0].children) - 1])
                        for i in screen.children[0].children:
                            i.disabled = False
        self.secure()
        self.root.current = 'login'


class Client(Protocol):
    def __init__(self):
        self.username = None
        self.destination = None

    def connectionMade(self):  # note: after login fails, connectionMade may be called a full minute later.
        Logger.info("Established connection.")  # TODO: cause is queue. More testing required.
        application.succeed_connection()

    def dataReceived(self, data):
        data = data.decode().split('}')
        for i in data:
            if i:
                command = loads((i + '}').encode())
                if command['command'] == 'secure':
                    application.secure_server(command)
                elif command['command'] == '200':
                    application.login_ok(command)
                elif command['command'] == '201':
                    application.signup_ok(command)
                elif command['command'] == 'friend_key':
                    application.got_friend_key(command)
                elif command['command'] == '406':
                    application.username_taken(command)
                elif command['command'] == '401':
                    application.login_failed(command)
                elif command['command'] == 'friend_request':
                    add_request(command)
                    application.refresh()
                elif command['command'] == 'friend_accept':
                    application.accept_request_reply(command)
                elif command['command'] == 'message':
                    save_message(command, application.username)
                    application.load_messages(application.destination)


    def connectionLost(self, reason=connectionDone):
        Logger.info(reason.value)


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
        application.fail_connection()
        connector.connect()

    def clientConnectionLost(self, connector, reason):
        Logger.info('Application: Disconnected.')
        connector.connect()


application = ChatApp()

if __name__ == '__main__':
    ExceptionManager.add_handler(ExceptionWatchdog())

    """
    USED FOR BUILDING OF STANDALONE WINDOWS APP
    
    import os
    from kivy.resources import resource_add_path
    
    if hasattr(sys, '_MEIPASS'):
        resource_add_path(os.path.join(sys._MEIPASS))"""

    application.run()
