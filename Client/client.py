import time
from io import BytesIO
from os.path import basename
from tkinter import filedialog, Tk
from os import environ

from appdirs import user_data_dir
from twisted.logger import globalLogPublisher, LogLevel

path = user_data_dir("PenguChat")
environ['KIVY_NO_ENV_CONFIG'] = '1'
environ["KCFG_KIVY_LOG_LEVEL"] = "error"
environ["KCFG_KIVY_LOG_DIR"] = path + '/PenguChat/Logs'

tkWindow = Tk()  # create a tkinter window, this is used for the native file dialogs
tkWindow.withdraw()  # hide it for now
# init must be done here, to ensure tkinter gets loaded b4 everything else

from builtins import IndexError
from pickle import dumps as p_dumps
from base64 import b64encode
from json import dumps, loads
from sys import modules
from kivy.app import App
from kivy.clock import Clock
from kivy.config import Config
from kivy.support import install_twisted_reactor
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from pyDH import DiffieHellman
from DBHandler import *

if 'twisted.internet.reactor' in modules:
    del modules['twisted.internet.reactor']
install_twisted_reactor()  # integrate twisted with kivy

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory
from twisted.protocols.basic import FileSender
#from twisted.python.log import startLogging
from twisted.internet.defer import Deferred
#from sys import stdout

#startLogging(stdout)

from UIElements import *

def analyze(event):
    if event.get("log_level") == LogLevel.critical:
        print ("Stopping for: ", event)

class FauxMessage:
    def __init__(self):
        self.isfile = None
        self.message_data = None
        self.sender = None


class PenguChatApp(App):  # this is the main KV app
    _popup: Popup

    def __init__(self):  # set the window params, as well as init some parameters
        super(PenguChatApp, self).__init__()
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
        self.pwd = None
        self.incoming = {}

    """App loading section"""

    @staticmethod
    def hide_tk(*args, **kwargs):
        tkWindow.withdraw()

    def build(self):
        super(PenguChatApp, self).build()
        self.root.current = 'loading_screen'  # move to the loading screen
        self.factory = ClientFactory()
        self.root.ids.conversation.bind(minimum_height=self.root.ids.conversation.setter('height'))
        self.root.ids.request_button.tab = 'F'
        self.icon = 'Assets/circle-cropped.png'
        reactor.connectTCP("localhost", 8123, self.factory)  # connect to the server

    """Server handshake, establish E2E tunnel for password exchange"""

    def secure(self):
        self.private = DiffieHellman()  # private key is generated
        public = self.private.gen_public_key()  # public key is derived from it
        command_packet = {
            'command': 'secure',
            'key': public
        }
        self.factory.client.transport.write((dumps(command_packet) + '\r\n').encode())  # send
        # print(f" <- {dumps(command_packet).encode()}")

    """Methods that send data to server"""

    def send_login_data(self):
        pwd = self.root.ids.loginPass.text  # get username and password from the UI element
        self.username = self.root.ids.loginUsr.text
        try:  # this block is necessary to make sure that an E2E tunnel exists to the server
            cipher = AES.new(str(self.server_key).encode(), AES.MODE_SIV)
        except AttributeError:  # if not, connection should be reset in order to get one
            self.factory.client.transport.loseConnection()
            self.fail_connection()
            return False
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())  # this generates a digest file from the pass
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'sender': self.username,
            'isfile': False
        }
        self.root.current = 'loading_screen'
        self.factory.client.transport.write((dumps(login_packet) + '\r\n').encode())  # finally, send it
        # print(f" <- {dumps(login_packet).encode()}")

    def send_sign_up_data(self):  # see above method, it's that but with extra steps
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
            self.factory.client.transport.write((dumps(signup_packet) + '\r\n').encode())
            # print(f" <- {dumps(signup_packet).encode()}")

    def logout(self):
        self.factory.client.transport.loseConnection()
        self.root.current = 'loading_screen'
        self.init_chat_room()  # called to clear the chat room, in anticipation of a new one being loaded

    @staticmethod
    def get_network_speed(*args, **kwargs):
        size = kwargs['size'] * (10 ** -6)
        delta = time.time() - kwargs['start']
        print(f"Transfer speed is {int(size / delta * 100)/100 } MBps")
        # print(size)

    def send_file(self, sender, destination, timestamp):
        blob = get_file_for_message(sender, destination, timestamp)
        blob = BytesIO(blob)
        sender = FileSender()
        sender.CHUNK_SIZE = 2 ** 16
        start_time = time.time()
        d = sender.beginFileTransfer(blob, self.factory.client.transport)
        #d.addCallback(self.get_network_speed, start=start_time, size=blob.getbuffer().nbytes)

    def send_text(self):
        message_text = self.root.ids.message_content.text
        self.root.ids.message_content.text = ""  # clear the message box's contents
        cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)  # encryption part
        content = p_dumps(cipher.encrypt_and_digest(message_text.encode()))
        content = b64encode(content).decode()
        packet = {
            'sender': self.username,
            'destination': self.destination,
            'command': 'message',
            'content': content,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False,
        }
        save_message(packet, self.username)
        f = FauxMessage()
        f.isfile = packet['isfile']
        f.message_data = packet['content']
        f.sender = packet['sender']

        self.add_bubble_to_conversation(f, self.destination)
        self.factory.client.transport.write((dumps(packet) + '\r\n').encode())
        # print(f" <- {dumps(packet).encode()}")

    def attach_file(self):  # function for attaching and then sending file
        file = filedialog.askopenfile(mode="rb")
        tkWindow.update()
        self.hide_tk()
        if file:
            file_data = p_dumps({'filename': basename(file.name), 'file_blob': file.read()})
            cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)  # encryption part
            blob = p_dumps(cipher.encrypt_and_digest(file_data)) + '\r\n'.encode()
            blob = b64encode(blob)
            blob += b'\r\n'

            cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)
            encrypted_name = p_dumps(cipher.encrypt_and_digest(basename(file.name).encode()))
            encrypted_name = b64encode(encrypted_name).decode()

            packet = {
                'sender': self.username,
                'destination': self.destination,
                'command': 'prepare_for_file',
                'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                'content': blob,
                'isfile': True,
                'filename': encrypted_name
            }
            save_message(packet, self.username, filename=basename(file.name))
            packet['content'] = ""
            packet['isfile'] = None
            f = FauxMessage()
            f.isfile = True
            f.truncated = packet
            f.sender = packet['sender']
            f.destination = packet['destination'],
            f.timestamp = datetime.strptime(packet['timestamp'], "%m/%d/%Y, %H:%M:%S")
            self.add_bubble_to_conversation(f, self.destination)
            self.conversation_refs[-1].switch_mode()
            self.root.ids['send_button'].disabled = True
            application.root.ids['attach_button'].disabled = True
            self.root.ids['message_content'].disabled = True
            self.factory.client.transport.write((dumps(packet) + '\r\n').encode())
            # print(f" <- {dumps(packet).encode()}")

    """Helper methods"""

    def set_sidebar_tab(self):  # changes sidebar tab to either the friend list or to the requests list
        try:
            if self.root.ids.request_button.tab == 'F':
                self.root.ids.request_button.tab = 'R'
                self.set_sidebar_to_request_list()
            elif self.root.ids.request_button.tab == 'R':
                self.root.ids.request_button.tab = 'F'
                self.set_sidebar_to_friend_list()
        except IndexError:
            pass

    def secure_server(self, command):  # part of the initial E2E
        self.server_key = self.private.gen_shared_key(command['content'])
        self.root.current = 'login'

    def login_ok(self):  # called when login succeeds, changes to the chatroom screen
        for screen in self.root.screens:  # clean any errors that may have appeared. This is ugly. Too bad!
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

    def signup_ok(self):  # ditto above, only for signup
        for screen in self.root.screens:
            if screen.name == 'signup':  # same ugliness
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

        pwd = self.pwd  # after the server verifies that the user was correctly registered, also log
        # him in.
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
        Clock.usleep(50000)  # give the client time to catch up and the server to log the user in
        self.factory.client.transport.write((dumps(login_packet) + '\r\n').encode())
        # print(f" <- {dumps(login_packet).encode()}")

    def got_friend_key(self, command):  # called when a common key is established with a partner, after the req.
        add_common_key(command['friend'],
                       self.private.gen_shared_key(command['content']),
                       self.username)

    def username_taken(self):  # called to change the screen to an errored state
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

    def login_failed(self):  # called when the signup process fails.
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

    def new_chat(self):  # called when sending a chat request

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
            self.factory.client.transport.write((dumps(packet) + '\r\n').encode())
            # print(f" <- {dumps(packet).encode()}")
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

    def accept_request(self, button_object):  # called when accepting the request
        friend = button_object.parent.parent.username  # Must move up two boxes, first parent is ver box second is hor
        friend_key = int(get_key_for_request(self.username, friend).decode())
        common_key = self.private.gen_shared_key(friend_key)
        add_common_key(friend, common_key, self.username)  # add the common key to the database
        self.root.ids.sidebar.remove_widget(button_object.parent)  # remove the request entry in the sidebar
        delete_request(friend)  # also delete the request from the db
        packet = {
            'sender': self.username,
            'command': 'friend_accept',
            'content': self.private.gen_public_key(),
            'destination': friend,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        start_message = {  # ths is a blank, ignored packed designed to allow an empty chat room to be displayed
            'sender': packet['destination'],
            'destination': packet['sender'],
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        save_message(start_message, self.username)  # save it
        del self.sidebar_refs[friend]
        self.set_sidebar_to_friend_list()
        self.factory.client.transport.write((dumps(packet) + '\r\n').encode())  # send the acknowledgement
        # print(f" <- {dumps(packet).encode()}")

    def accept_request_reply(self, packet):  # called when the peer has accepted the chat request
        private = DiffieHellman()
        private._DiffieHellman__a = get_private_key(packet['sender'], self.username)
        common = private.gen_shared_key(int(packet['content']))  # Maybe Done: Sometimes getting errors. Why?
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

    def deny_request(self, button_object):  # called when denying the request
        self.root.ids.sidebar.remove_widget(button_object)
        del self.sidebar_refs[button_object.parent.parent.username]
        delete_request(button_object.parent.parent.username)
        self.set_sidebar_to_request_list()

    """Loading methods"""

    def set_sidebar_to_friend_list(self):  # set sidebar to the friends list
        self.root.ids.sidebar.clear_widgets()  # clear all items in the sidebar
        self.root.ids.req.source = 'Assets/requests.png'
        self.root.ids.request_button.text = f"{len(get_requests(self.username))}\n"  # change the sidebar button
        self.root.ids.request_button.on_press = self.set_sidebar_to_request_list  # text

        names = get_friends(self.username)  # call the database to see who the prev conversations were

        for i in names:  # create a new button for every friend
            a = MenuButton(text=i)
            a.bind(on_press=self.show_message_box)
            self.root.ids.sidebar.rows += 1
            self.root.ids.sidebar.add_widget(a)
            self.friend_refs.append(a)
        self.root.ids.request_button.canvas.ask_update()

    def set_sidebar_to_request_list(self):  # pretty much ditto set_sidebar_to_friend_list, see above
        self.root.ids.sidebar.clear_widgets()
        self.root.ids.request_button.text = ""
        self.root.ids.req.source = 'Assets/conversation.png'

        """Image:
        source: 'Assets/requests.png'
        size: self.parent.size
        pos: (self.parent.pos[0] - 1, self.parent.pos[1])"""

        self.root.ids.request_button.on_press = self.set_sidebar_to_friend_list

        requests = get_requests(self.username)  # fixed
        for i in requests:
            e = SidebarElement(i)

            e.accept.bind(on_press=self.accept_request)
            e.decline.bind(on_press=self.deny_request)
            self.sidebar_refs[i] = e
            self.root.ids.sidebar.rows += 1
            self.root.ids.sidebar.add_widget(e.container)
        self.root.ids.request_button.canvas.ask_update()

    def load_messages(self, partner):  # method to load all the messages
        if len(self.conversation_refs) > 0:  # clear the conversation
            self.root.ids.conversation.clear_widgets()
            self.conversation_refs.clear()
            self.root.ids.conversation.rows = 0

        messages = get_messages(partner, self.username)  # call the database to get the messages
        for i in messages:  # decrypt every message and then display it
            self.add_bubble_to_conversation(i, partner)

    def ingest_file(self, buffer):

        cipher = AES.new(get_common_key(self.username, self.incoming['sender']), AES.MODE_SIV)
        encrypted_filename = p_loads(b64decode(self.incoming['filename']))

        self.incoming['isfile'] = True
        self.incoming['sender'] = self.incoming['sender']  # TODO: ?
        self.incoming['content'] = buffer.strip(b'\r\n')
        self.incoming['timestamp'] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        filename = cipher.decrypt_and_verify(encrypted_filename[0], encrypted_filename[1]).decode()

        save_message(self.incoming, self.username, filename)
        f = FauxMessage()
        f.isfile = self.incoming['isfile']
        f.message_data = self.incoming['content']
        f.sender = self.incoming['sender']
        f.destination = self.username
        f.timestamp = self.incoming['timestamp']

        application.add_bubble_to_conversation(f, self.incoming['sender'])
        # print("ingest complete")

    def add_bubble_to_conversation(self, message, partner):
        cipher = AES.new(get_common_key(partner, self.username), AES.MODE_SIV)
        if not message.isfile:
            encrypted = p_loads(b64decode(message.message_data))
            try:
                message.message_data = cipher.decrypt_and_verify(encrypted[0], encrypted[1]).decode()
            except ValueError:
                Logger.error(f"Application: MAC error on message id {message.id}")
                message.message_data = "[Message decryption failed. Most likely the key has changed]"
            finally:
                if message.sender == self.username:
                    e = ConversationElement(side='r', isfile=False, text=message.message_data)
                else:
                    e = ConversationElement(side='l', isfile=False, text=message.message_data)
        else:
            filename = get_filename(message.sender,
                                    message.destination,
                                    message.timestamp
                                    )
            truncated = {
                'sender': message.sender,
                'destination': message.destination,
                'timestamp': message.timestamp
            }
            if message.sender == self.username:
                e = ConversationElement(side='r', isfile=True, filename=filename, truncated=truncated)

            else:
                e = ConversationElement(side='l', isfile=True, filename=filename, truncated=truncated)

        self.root.ids.conversation.rows += 1
        self.root.ids.conversation.add_widget(e.line)
        self.conversation_refs.append(e)
        Clock.schedule_once(e.reload, 0.01)  # addresses the bug where the long messages do not display properly

    def init_chat_room(self):  # called upon first entering the chatroom
        self.hide_message_box()
        self.set_sidebar_to_friend_list()
        self.root.ids.conversation.clear_widgets()

    """Widget methods"""

    def show_message_box(self, button_object):  # show the message box down TODO: text is blue. Why is text blue?
        self.destination = button_object.text
        self.root.ids.message_box.foreground_color = (0, 0, 0)
        if self.check_if_hidden(self.root.ids.message_box):
            self.show_widget(self.root.ids.message_box)
        self.load_messages(self.destination)

    def hide_message_box(self):  # hide the message box
        self.hide_widget(self.root.ids.message_box)

    def hide_widget(self, widget):  # helper method designed to hide widgets
        if not self.check_if_hidden(widget):
            wid = widget
            wid.saved_attrs = wid.height, wid.size_hint_y, wid.opacity, wid.disabled
            wid.height, wid.size_hint_y, wid.opacity, wid.disabled = 0, None, 0, True
            widget = wid
            if widget:
                pass

    def show_widget(self, widget):  # reverse of above
        wid = widget
        if self.check_if_hidden(widget):
            wid.height, wid.size_hint_y, wid.opacity, wid.disabled = wid.saved_attrs
            del wid.saved_attrs
            widget = wid
            if widget:
                pass

    """Static methods"""

    @staticmethod
    def check_if_hidden(widget):  # needed to check if widget was hidden
        try:
            widget.saved_attrs
        except AttributeError:
            return False
        else:
            return True

    def fail_connection(self):  # called when connection has failed
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

    def succeed_connection(self):  # called when connection succeeds, usually after a failed connection
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


class Client(Protocol):  # defines the communications protocol
    def __init__(self):
        self.username = None
        self.destination = None
        self.receiving_file = False
        self.buffer = b""

    def connectionMade(self):
        Logger.info("Established connection.")  # note: all queue mechanisms were removed once 1.3 rolled around
        application.succeed_connection()

    def dataReceived(self, data):  # called when a packet is received.
        if not self.receiving_file:
            #print(f" -> {data}")       # uncomment this line to get the raw packet data
            data = data.decode().split('}')
            for packet in data:
                if packet:
                    command = loads((packet + '}').encode())
                    if command['command'] == 'secure':
                        application.secure_server(command)
                    elif command['command'] == '200':
                        application.login_ok()
                    elif command['command'] == '201':
                        application.signup_ok()
                    elif command['command'] == 'friend_key':
                        application.got_friend_key(command)
                    elif command['command'] == '406':
                        application.username_taken()
                    elif command['command'] == '401':
                        application.login_failed()
                    elif command['command'] == 'friend_request':
                        add_request(command)
                        application.root.ids.request_button.text = f"{len(get_requests(application.username))}\n"
                    elif command['command'] == 'friend_accept':
                        application.accept_request_reply(command)
                    elif command['command'] == 'message':
                        save_message(command, application.username)
                        f = FauxMessage()
                        f.isfile = command['isfile']
                        f.message_data = command['content']
                        f.sender = command['sender']
                        application.add_bubble_to_conversation(f, command['sender'])
                    elif command['command'] == 'ready_for_file':
                        application.send_file(
                            command['original_sender'],
                            command['original_destination'],
                            command['timestamp']
                        )
                    elif command['command'] == 'prepare_for_file':
                        application.incoming = command
                        application.incoming['sender'] = command['original_sender']
                        application.incoming['filename'] = command['filename']
                        self.receiving_file = True
                        # print("In file transfer mode")
                        packet = {
                            'sender': command['destination'],
                            'destination': command['sender'],
                            'command': 'ready_for_file'
                        }
                        application.factory.client.transport.write(dumps(packet).encode())
                        # print(f" <- {dumps(packet).encode()}")
                    elif command['command'] == 'file_received':
                        application.conversation_refs[-1].switch_mode()
                        application.root.ids['send_button'].disabled = False
                        application.root.ids['attach_button'].disabled = False
                        application.root.ids['message_content'].disabled = False
        else:
            # print(f" -> [ FILE BLOB DATA ]")
            self.buffer += data
            if self.buffer[-2:] == '\r\n'.encode():
                #   print("File transfer complete")
                application.ingest_file(self.buffer)
                self.receiving_file = False
                self.buffer = b""
            #   print("Successfully ingested. All done.")

    def connectionLost(self, reason=connectionDone):  # called when the connection dies. RIP.
        Logger.info(reason.value)


class ClientFactory(Factory):  # handles connections and communications
    def __init__(self):
        self.client = None

    def buildProtocol(self, addr):
        c = Client()
        self.client = c
        return c

    def startedConnecting(self, connector):
        Logger.info('Application: Attempting to connect...')

    def clientConnectionFailed(self, connector, reason):
        Logger.error('Application: Connection failed!')
        application.fail_connection()
        connector.connect()

    def clientConnectionLost(self, connector, reason):
        Logger.info('Application: Disconnected.')
        connector.connect()


application = PenguChatApp()

if __name__ == '__main__':
    """ 
    THIS IS NECESSARY FOR PYINSTALLER BUILD ON WINDOWS. DO NOT UNCOMMENT UNLESS BUILDING.
    import os
    from kivy.resources import resource_add_path

     if hasattr(sys, '_MEIPASS'):
        resource_add_path(os.path.join(sys._MEIPASS))
     """

    globalLogPublisher.addObserver(analyze)
    application.run()
    ExceptionManager.add_handler(ExceptionWatchdog())
