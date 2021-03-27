from os import environ

from appdirs import user_data_dir
from kivy.uix.image import Image

path = user_data_dir("PenguChat")
environ['KIVY_NO_ENV_CONFIG'] = '1'
environ["KCFG_KIVY_LOG_LEVEL"] = "error"
environ["KCFG_KIVY_LOG_DIR"] = path + '/PenguChat/Logs'

from base64 import b64decode
from tkinter.filedialog import SaveAs, asksaveasfile

from Crypto.Cipher import AES
from kivy import Logger, LOG_LEVELS

from Client.DBHandler import get_common_key, get_file_for_message

Logger.setLevel(LOG_LEVELS["error"])
from kivy.base import ExceptionHandler, ExceptionManager
from kivy.graphics.context_instructions import Color
from kivy.graphics.vertex_instructions import Rectangle, RoundedRectangle, Ellipse
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.widget import Widget

from pickle import loads as p_loads

# houses the UI elements that couldn't be defined in the KV

colors = {
    'red': (1, 0, 0),
    'gray': (0.4, 0.4, 0.4),
    'menu_blue': (0, 0.413, 0.586),
    'menu_light_blue': (0.096, 0.535, 0.656),
    'outgoing_message': (0.096, 0.535, 0.656),
    'incoming_message': (0, 0.213, 0.28)
}


class MenuButton(Button):
    pass


class BackgroundContainer(BoxLayout):
    pass


class EmptyWidget(Widget):
    def update_rect(self):
        pass

    def __init__(self, **kwargs):
        super(EmptyWidget, self).__init__(**kwargs)
        self.size_hint_x = 1
        self.size_hint_y = 0
        self.height = 0

    pass


class ColoredLabel(Label):
    def __init__(self, color='gray', **kwargs):
        super(ColoredLabel, self).__init__(**kwargs)
        with self.canvas.before:
            self.background_color = Color()
            self.background_color.rgb = colors[color]
            self.rect = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, value, new_position):
        self.rect.pos = self.pos
        self.rect.size = self.size


class MessageBubble(Label):
    def __init__(self, side, **kwargs):
        super(MessageBubble, self).__init__(**kwargs)
        with self.canvas.before:
            self.background_color = Color()
            self.background_color.rgb = (0, 0, 0)
            self.rect = RoundedRectangle(pos=self.pos, size=self.texture_size)
            self.rect.radius = [(15, 15), (15, 15), (15, 15), (15, 15)]
            self.side = side

        self.bind(pos=self.update_rect)

    def update_rect(self, value=None, new_position=None, **kwargs):
        self.rect.pos = (self.parent.width - self.width, self.pos[1]) \
            if self.side == 'r' \
            else self.pos
        self.rect.size = self.size
        if self.width > 0.75 * self.parent.width:
            self.text_size[0] = 0.75 * self.parent.width
        self.parent.height = self.height


class FileBubble(Button):
    def __init__(self, side, text, truncated, **kwargs):
        super(FileBubble, self).__init__(**kwargs)
        self.background_color = (0, 0, 0, 0)
        if len(text) > 10:
            text = text[0:3] + "..." + text[text.rfind("."):]
        with self.canvas.before:
            self.bc = Color()
            self.bc.rgb = colors['incoming_message'] if side == 'l' else colors['outgoing_message']
            self.rect = RoundedRectangle(pos=self.pos, size=(150, 150))
            self.rect.radius = [(15, 15), (15, 15), (15, 15), (15, 15)]
            self.side = side


            self.text = f'\n\n\n{text}'
            self.truncated = truncated
        with self.canvas.after:
            self.im = Image(source="Assets/file.png")

        self.im.anim_delay = 0.01
        self.bind(pos=self.update_rect)
        self.bind(on_press=self.callback)

    def update_rect(self, *args, **kwargs):
        self.rect.pos = (self.parent.width - self.width, self.pos[1]) \
            if self.side == 'r' \
            else self.pos
        self.font_size = 0.15 * self.width
        self.rect.size = self.size

        self.im.pos = (self.parent.width - self.width, self.pos[1] + 15) \
            if self.side == 'r' \
            else (self.pos[0], self.pos[1] + 15)
        self.im.size = self.size

        self.parent.height = self.height

    def callback(self, *args, **kwargs):
        cipher = AES.new(get_common_key(self.truncated['destination'], self.truncated['sender']), AES.MODE_SIV)
        buffered = get_file_for_message(self.truncated['sender'],
                                        self.truncated['destination'],
                                        self.truncated['timestamp']
                                        )
        encrypted = p_loads(b64decode(buffered))
        data = p_loads(cipher.decrypt_and_verify(encrypted[0], encrypted[1]))
        f = asksaveasfile(mode='wb+', initialfile=data['filename'])
        if f is None:
            return
        f.write(data['file_blob'])
        f.close()


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
    def switch_mode(self):
        load = "Assets/processing.gif"
        static = "Assets/file.png"
        if not self.loading:
            if self.side == 'l':
                self.left.im.source = load
            else:
                self.right.im.source = load
        else:
            if self.side == 'r':
                self.right.im.source = static
            else:
                self.left.im.source = static
        self.loading = not self.loading

    def __init__(self, text=None, side=None, isfile=False, filename=None, truncated=None):
        self.line = BoxLayout(orientation='horizontal')
        self.left = None
        self.right = None
        self.line.size_hint_y = None
        self.reload = None
        self.loading = False
        self.side = side

        if side == 'l':
            self.left = MessageBubble(text=text, side=side) if not isfile \
                else FileBubble(side=side, text=filename, truncated=truncated)
            self.left.background_color.rgb = colors['incoming_message']
            self.right = EmptyWidget()
            self.reload = self.left.update_rect
        else:
            self.right = MessageBubble(text=text, side=side) if not isfile \
                else FileBubble(side=side, text=filename, truncated=truncated)
            self.right.background_color.rgb = colors['outgoing_message']
            self.left = EmptyWidget()
            self.reload = self.right.update_rect

        self.line.add_widget(self.left)
        self.line.add_widget(self.right)
        # self.line.add_widget(a)
