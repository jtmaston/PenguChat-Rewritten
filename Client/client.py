from os.path import basename
from tkinter import filedialog, Tk

tkWindow = Tk()  # create a tkinter window, this is used for the native file dialogs
tkWindow.withdraw()  # hide it for now
# init must be done here, to ensure tkinter gets loaded b4 everything else

from builtins import IndexError
from pickle import dumps as p_dumps
from pickle import loads as p_loads
from base64 import b64encode, b64decode
from json import dumps, loads
from sys import modules
from Crypto.Cipher import AES
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
from UIElements import *




class ChatApp(App):  # this is the main KV app
    _popup: Popup

    def __init__(self):  # set the window params, as well as init some parameters
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        #Config.set('graphics', 'fullscreen', '0')
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
        self.root.current = 'loading_screen'  # move to the loading screen
        self.factory = ClientFactory()
        self.root.ids.conversation.bind(minimum_height=self.root.ids.conversation.setter('height'))
        reactor.connectTCP("localhost", 8123, self.factory)  # connect to the server

    """Server handshake, establish E2E tunnel for password exchange"""

    def secure(self):
        self.private = DiffieHellman()  # private key is generated
        public = self.private.gen_public_key()  # public key is derived from it
        command_packet = {
            'command': 'secure',
            'key': public
        }
        self.factory.client.transport.write(dumps(command_packet).encode())  # send

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
        self.factory.client.transport.write(dumps(login_packet).encode())  # finally, send it

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
            self.factory.client.transport.write(dumps(signup_packet).encode())

    def logout(self):
        self.factory.client.transport.loseConnection()
        self.root.current = 'loading_screen'
        self.init_chat_room()  # called to clear the chat room, in anticipation of a new one being loaded

    def send(self, isfile=False, file=None):
        message_text = self.root.ids.message_content.text
        self.root.ids.message_content.text = ""  # clear the message box's contents
        cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)  # encryption part
        if not isfile:
            content = p_dumps(cipher.encrypt_and_digest(message_text.encode()))
            content = b64encode(content).decode()
        else:
            file_data = p_dumps({'filename': basename(file.name), 'file_blob': file.read()})
            content = p_dumps(cipher.encrypt_and_digest(file_data))
            content = b64encode(content).decode()
        packet = {
            'sender': self.username,
            'destination': self.destination,
            'command': 'message',
            'content': content,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False if not isfile else True
        }
        save_message(packet, self.username)  # first, save it to the database.
        self.factory.client.transport.write(dumps(packet).encode())  # send it
        self.load_messages(self.destination)  # finally, reload the conversation, so that the new messages are displayed

    def attach_file(self):  # function for attaching and then sending file
        file = filedialog.askopenfile(mode="rb")
        if file is not None:
            self.send(isfile=True, file=file)

    """Helper methods"""

    def set_sidebar_tab(self):  # changes sidebar tab to either the friend list or to the requests list
        try:
            if self.root.ids.request_button.text[0] == 'F':
                self.set_sidebar_to_request_list()
            elif self.root.ids.request_button.text[0] == 'R':
                self.set_sidebar_to_friend_list()
        except IndexError:
            pass

    def secure_server(self, command):  # part of the initial E2E
        self.server_key = self.private.gen_shared_key(command['content'])
        self.root.current = 'login'

    def login_ok(self, command):  # called when login succeeds, changes to the chatroom screen
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

    def signup_ok(self, command):  # ditto above, only for signup
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
        self.factory.client.transport.write(dumps(login_packet).encode())

    def got_friend_key(self, command):  # called when a common key is established with a partner, after the req.
        add_common_key(command['friend'],
                       self.private.gen_shared_key(command['content']),
                       self.username)

    def username_taken(self, command):  # called to change the screen to an errored state
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

    def login_failed(self, command):  # called when the signup process fails.
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
        self.factory.client.transport.write(dumps(packet).encode())  # send the acknowledgement

    def accept_request_reply(self, packet):  # called when the peer has accepted the chat request
        private = DiffieHellman()
        private._DiffieHellman__a = get_private_key(packet['sender'], self.username)
        common = private.gen_shared_key(int(packet['content']))  # Maybe Done: Sometimes getting errors. Why?
        add_common_key(packet['sender'], common, self.username)  # TODO: investigate
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
        self.root.ids.sidebar.remove_widget(button_object.parent)
        del self.sidebar_refs[button_object.parent.parent.username]
        delete_request(button_object.parent.parent.username)

    """Loading methods"""

    def set_sidebar_to_friend_list(self):  # set sidebar to the friends list
        self.root.ids.sidebar.clear_widgets()  # clear all items in the sidebar
        #self.root.ids.request_button.text = f"Requests ({len(get_requests(self.username))})"  # change the sidebar button
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

    def load_messages(self, partner):  # method to load all the messages
        if len(self.conversation_refs) > 0:  # clear the conversation
            self.root.ids.conversation.clear_widgets()
            self.conversation_refs.clear()
            self.root.ids.conversation.rows = 0

        messages = get_messages(partner, self.username)  # call the database to get the messages

        for i in messages:  # decrypt every message and then display it
            cipher = AES.new(get_common_key(partner, self.username), AES.MODE_SIV)
            encrypted = p_loads(b64decode(i.message_data))
            if not i.isfile:
                try:
                    i.message_data = cipher.decrypt_and_verify(encrypted[0], encrypted[1]).decode()
                except ValueError:
                    Logger.error(f"Application: MAC error on message id {i.id}")
                    i.message_data = "[Message decryption failed. Most likely the key has changed]"
                finally:
                    if i.sender == self.username:
                        e = ConversationElement(text=i.message_data, side='r')
                    else:
                        e = ConversationElement(text=i.message_data, side='l')
            else:
                try:
                    file_data = p_loads(cipher.decrypt_and_verify(encrypted[0], encrypted[1]))
                except ValueError:
                    Logger.error(f"Application: MAC error on message id {i.id}")
                    file_data['filename'] = "[Message decryption failed. Most likely the key has changed]"
                finally:
                    if i.sender == self.username:
                        e = ConversationElement(side='r', isfile=True, filedata=file_data)
                    else:
                        e = ConversationElement(side='l', isfile=True, filedata=file_data)
            self.root.ids.conversation.rows += 1
            self.root.ids.conversation.add_widget(e.line)
            self.conversation_refs.append(e)

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

    @staticmethod
    def disable_fullscreen():
        #Config.set('graphics', 'fullscreen', '0')
        # Config.write()
        pass

    @staticmethod
    def enable_fullscreen():
        #Config.set('graphics', 'fullscreen', '1')
       # Config.write()
        pass

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


class Client(Protocol):  # defines the comms protocol
    def __init__(self):
        self.username = None
        self.destination = None

    def connectionMade(self):
        Logger.info("Established connection.")  # note: all queue mechanisms were removed once 1.3 rolled around
        application.succeed_connection()

    def dataReceived(self, data):  # called when a packet is received.
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
                    application.set_sidebar_tab()
                elif command['command'] == 'friend_accept':
                    application.accept_request_reply(command)
                elif command['command'] == 'message':
                    save_message(command, application.username)
                    application.load_messages(application.destination)

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
