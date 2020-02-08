from kivy.config import Config
from kivy.app import App
from Auth import *
from easygui import fileopenbox

from imagecropper import create_thumbnail


class ChatApp(App):
    def __init__(self):
        """Set login page size and screen"""
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        self.handler = DBHandler()

    def on_request_close(self, timestamp):
        self.stop()

    def sign_up(self):
        self.root.current = 'signup'

    def upload_image(self):
        path = fileopenbox()
        create_thumbnail(path)
        print(path)


if __name__ == '__main__':
    ChatApp().run()
