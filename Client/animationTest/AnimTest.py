from kivy import Config
from kivy.app import App


class AnimTest(App):  # this is the main KV app

    def __init__(self):  # set the window params, as well as init some parameters
        super(AnimTest, self).__init__()
        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '700')


    def build(self):
       super(AnimTest, self).build()
       self.root.current = 'login'


if __name__ == '__main__':
    AnimTest().run()