# os.environ["KIVY_NO_CONSOLELOG"] = "1"

from kivy.config import Config
from kivy.app import App
from kivy.uix.button import Button
import bcrypt
from Client.client import kbQueue
from Client.client import ClientFactory
from twisted.internet import reactor


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


if __name__ == '__main__':
    ChatApp().run()
