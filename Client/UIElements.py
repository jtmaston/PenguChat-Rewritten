from kivy.base import ExceptionHandler, ExceptionManager
from kivy.graphics.context_instructions import Color
from kivy.graphics.vertex_instructions import Rectangle
from kivy.properties import ObjectProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.widget import Widget
from kivy import Logger


# houses the UI elements that couldn't be defined in the KV


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