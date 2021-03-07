from kivy import Logger
from kivy.base import ExceptionHandler, ExceptionManager
from kivy.graphics.context_instructions import Color
from kivy.graphics.vertex_instructions import Rectangle, RoundedRectangle
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.widget import Widget

# houses the UI elements that couldn't be defined in the KV

colors = {
    'red': (1, 0, 0),
    'gray': (0.4, 0.4, 0.4),
    'menu_blue': (0, 0.413, 0.586),
    'menu_light_blue': (0.096, 0.535, 0.656)
}


class MessageLabelLeft(Label):
    pass


class RightFile(Button):
    def __init__(self, filedata=None, **kwargs):
        super(RightFile, self).__init__(**kwargs)
        self.text = filedata['filename']
        self.file_data = filedata['file_blob']


class LeftFile(Button):
    pass


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


class MessageLabelRight(Label):
    def __init__(self, **kwargs):
        super(MessageLabelRight, self).__init__(**kwargs)
        with self.canvas.before:
            self.background_color = Color()
            self.background_color.rgb = (0.096, 0.535, 0.656)
            self.rect = RoundedRectangle(pos=self.pos, size=self.texture_size)
            self.rect.radius = [(15, 15), (15, 15), (15, 15), (15, 15)]
        self.bind(pos=self.update_rect)

    def update_rect(self, value, new_position):
        self.rect.pos = (self.parent.width - self.width, self.pos[1])
        self.rect.size = self.size
        if self.width > self.parent.width / 2:
            self.text_size[0] = self.parent.width / 2
        self.parent.height = self.height

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

    def __init__(self, text=None, side=None, isfile=False, filedata=None):
        self.line = BoxLayout(orientation='horizontal')
        self.left = None
        self.right = None
        self.line.size_hint_y = None

        if side == 'l':
            self.left = MessageLabelLeft(text=text) if not isfile else LeftFile(filedata)
            self.right = EmptyWidget()
        else:
            self.right = MessageLabelRight(text=text) if not isfile else MenuButton(text=filedata['filename'])
            self.left = EmptyWidget()

        self.line.add_widget(self.left)
        self.line.add_widget(self.right)
        # self.line.add_widget(a)
