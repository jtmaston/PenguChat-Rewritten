from json import dumps, loads


class BasePacket:
    def __init__(self):
        self.username = None
        self.command = None

    def load(self, packet_string):
        packet = loads(packet_string)
        self.username = packet['username']
        self.command = packet['command']

    def dump(self):
        return dumps(self.__dict__).encode('UTF-8')


class AuthPacket(BasePacket):
    def __init__(self):
        super(AuthPacket, self).__init__()
