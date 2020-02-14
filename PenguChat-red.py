from kivy.config import Config
from kivy.app import App
from kivy.support import install_twisted_reactor
from kivy.uix.image import Image
from kivy.core.image import Image as CoreImage
from easygui import fileopenbox
import bcrypt
from imagecropper import create_thumbnail
from Comms.client import kbQueue
from twisted.internet import reactor
from Comms.client import ClientFactory

install_twisted_reactor()


class ChatApp(App):
    def __init__(self):
        """Set login page size and screen"""
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        self.placeholder = Image(source="Assets/placehold.png")
        self.pfp_byte_arr = None
        reactor.connectTCP("localhost", 8123, ClientFactory())

    def on_request_close(self, timestamp):
        self.stop()

    def sign_up_redirect(self):
        self.root.current = 'signup'

    def sign_up(self):
        pwd = self.root.ids.passwd.text
        pwd_r = self.root.ids.passwd_r.text
        username = self.root.ids.username.text
        if pwd == pwd_r and self.pfp_byte_arr.getvalue() is not None:
            salt = bcrypt.gensalt()
            pwd = bcrypt.hashpw(pwd.encode(), salt)
            command = {'command': 'register', 'args': (username, pwd, salt)}
            kbQueue.put(command)

    def upload_image(self):
        path = fileopenbox(msg='Choose an image', filetypes=[['*.jpg', '*.jpeg', '*.bmp', '*.png', 'Image files']],
                           multiple=False)
        if path is not None:
            self.pfp_byte_arr = create_thumbnail(path)
            self.placeholder.texture = CoreImage(self.pfp_byte_arr, ext='png').texture
            self.root.current = 'signup'


if __name__ == '__main__':
    ChatApp().run()
