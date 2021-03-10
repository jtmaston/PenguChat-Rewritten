from tkinter.filedialog import SaveAs, asksaveasfile

from kivy import Logger, LOG_LEVELS

Logger.setLevel(LOG_LEVELS["error"])
from kivy.base import ExceptionHandler, ExceptionManager
from kivy.graphics.context_instructions import Color
from kivy.graphics.vertex_instructions import Rectangle, RoundedRectangle, Ellipse
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.widget import Widget

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
    def __init__(self, side, text, blob, **kwargs):
        super(FileBubble, self).__init__(**kwargs)
        self.background_color = (0, 0, 0, 0)
        with self.canvas.before:
            self.bc = Color()
            self.bc.rgb = colors['incoming_message'] if side == 'l' else colors['outgoing_message']
            self.rect = RoundedRectangle(pos=self.pos, size=(150, 150))
            self.rect.radius = [(15, 15), (15, 15), (15, 15), (15, 15)]
            self.side = side
            self.data = blob
            self.text =	f'\n\n\n{text}'

        self.bind(pos=self.update_rect)
        self.bind(on_press=self.callback)

    def update_rect(self, *args, **kwargs):
        self.rect.pos = (self.parent.width - self.width, self.pos[1]) \
            if self.side == 'r' \
            else self.pos
        self.font_size = 0.15 * self.width
        self.rect.size = self.size
        self.parent.height = self.height

    def callback(self, *args, **kwargs):
        f = asksaveasfile(mode='wb+', initialfile=self.text.strip())
        if f is None:
            pass
        f.write(self.data)
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

    def __init__(self, text=None, side=None, isfile=False, filedata=None):
        self.line = BoxLayout(orientation='horizontal')
        self.left = None
        self.right = None
        self.line.size_hint_y = None
        self.reload = None

        if side == 'l':
            self.left = MessageBubble(text=text, side=side) if not isfile \
                else FileBubble(side=side, text=filedata['filename'], blob=filedata['file_blob'])
            self.left.background_color.rgb = colors['incoming_message']
            self.right = EmptyWidget()
            self.reload = self.left.update_rect
        else:
            self.right = MessageBubble(text=text, side=side) if not isfile \
                else FileBubble(side=side, text=filedata['filename'], blob=filedata['file_blob'])
            self.right.background_color.rgb = colors['outgoing_message']
            self.left = EmptyWidget()
            self.reload = self.right.update_rect

        self.line.add_widget(self.left)
        self.line.add_widget(self.right)
        # self.line.add_widget(a)
