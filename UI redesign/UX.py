from kivy import Config
from kivy.app import App
from kivy.clock import Clock
from kivy.graphics.vertex_instructions import RoundedRectangle
from kivy.metrics import cm
from kivy.properties import ObjectProperty
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label


class MessageBubble(Label):
    body = ObjectProperty(None)

    def __init__(self, side, **kwargs):
        super(MessageBubble, self).__init__(**kwargs)
        self.size = (cm(5), cm(3))
        self.size_hint = (None, None)
        self.side = side
        self.text_size = self.size
        self.halign = 'center'
        self.valign = 'center'

        with self.canvas.before:
            self.body = RoundedRectangle()
            self.body.radius = [(20, 20), (20, 20), (20, 20), (20, 20)]
            self.body.size = self.size
            self.body.pos = self.pos


class UXApp(App):
    def __init__(self):
        super(UXApp, self).__init__()
        Config.set('graphics', 'width', '1080')
        Config.set('graphics', 'height', '720')
        self.layout = GridLayout(cols=2, spacing=10, size_hint_y=None)
        self.layout.bind(minimum_height=self.layout.setter('height'))
        self.message_list = []

    def build(self):
        self.root.current = "chat_room"
        a = Button(text="Placeholder name")
        self.root.sidebar.rows += 1
        self.root.sidebar.add_widget(a)

        btn = MessageBubble(text='Right', color=[0, 0, 0, 1], side='right')
        self.message_list.append(btn)
        self.layout.add_widget(Label())
        self.layout.add_widget(btn)

        btn = MessageBubble(text='Left', color=[0, 0, 0, 1], side='left')
        self.message_list.append(btn)
        self.layout.add_widget(btn)
        self.layout.add_widget(Label())

        self.root.conversation_box.add_widget(self.layout)
        Clock.schedule_once(self.update_backgrounds, 0.01)  # wait a little bit to render backgrounds

    def update_backgrounds(self, *args, **kwargs):
        for i in self.message_list:
            i.halign = i.side

            if i.side == 'left':
                i.pos[0] = 0
                i.padding_x = 20
            else:
                i.pos[0] = self.layout.size[0] - i.size[0]
                i.padding_x = -20

            i.body.pos = i.pos


if __name__ == '__main__':
    UXApp().run()
