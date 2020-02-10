from kivy.config import Config
from kivy.app import App
from kivy.uix.image import Image
from kivy.core.image import Image as CoreImage
from DatabaseHelper import *
from easygui import fileopenbox

from imagecropper import create_thumbnail


class ChatApp(App):
    def __init__(self):
        """Set login page size and screen"""
        super(ChatApp, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')
        self.placeholder = Image(source="assets/placeholder.png")

    def on_request_close(self, timestamp):
        self.stop()

    def sign_up(self):
        self.root.current = 'signup'

    def upload_image(self):
        path = fileopenbox(msg='Choose an image', filetypes=[['*.jpg', '*.jpeg', '*.bmp', '*.png', 'Image files']],
                           multiple=False)
        if path is not None:
            byteArr = create_thumbnail(path)
            self.placeholder.texture = CoreImage(byteArr, ext='png').texture
            self.root.current = 'signup'


if __name__ == '__main__':
    ChatApp().run()
