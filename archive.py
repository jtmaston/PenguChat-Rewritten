# def process_command_queue(self):
#     if not kbQueue.empty():
#         queued_command = kbQueue.get()
#         if queued_command['command'] == 'register':
#             packet = {
#                 'command': 'register',
#                 'username': queued_command['args'][0],
#                 'password': base64.b64encode(queued_command['args'][1]).decode(),
#                 'salt': base64.b64encode(queued_command['args'][2]).decode(),
#                 'pfp': base64.b64encode(queued_command['args'][3]).decode()
#             }
#             self.username = queued_command['args'][0]  # vcs
#             self.transport.write(json.dumps(packet).encode())
#         elif queued_command['command'] == 'send':
#             cipher = AES.new(str(self.common).encode(), AES.MODE_SIV)
#             plaintext = kbQueue.get()
#             encrypted, tag = cipher.encrypt_and_digest(plaintext.encode())
#             packet = {
#                 'command': 'send',
#                 'username': self.username,
#                 'destination': self.destination,
#                 'content': base64.b64encode(encrypted).decode(),
#                 'tag': base64.b64encode(tag).decode()
#             }
#             self.transport.write(json.dumps(packet).encode())
#
#         elif queued_command['command'] == 'login':
#             if self.common:
#                 self.call_for_salt(queued_command['args'][0])
#                 if not self.salt:
#                     print('going round')
#                     kbQueue.put(queued_command)
#                     return 0
#                 pwd = bcrypt.hashpw(queued_command['args'][1].encode(), self.salt.encode())
#                 packet = {
#                     'command': 'login',
#                     'username': queued_command['args'][0],
#                     'password': base64.b64encode(pwd).decode(),
#                 }
#                 self.transport.write(json.dumps(packet).encode())
#             else:
#                 kbQueue.put(queued_command)
#
#
# def call_for_salt(self, username):
#     packet = {
#         'command': 'salt',
#         'username': username,
#     }
#     self.transport.write(json.dumps(packet).encode())
#
#
# def disconnect(self):
#     print("Disconnected")
#     self.transport.loseConnection()
#
#     def dataReceived(self, data):
#         data = json.loads(data)
#
#         if data['command'] == 'send':
#             encrypted = base64.b64decode(data['content'].encode())
#             tag = base64.b64decode(data['tag'].encode())
#             cipher = AES.new(str(self.common).encode(), AES.MODE_SIV)
#             plain = cipher.decrypt_and_verify(encrypted, tag)
#             print(f'\r{data["username"]}: {plain.decode()}')
#
#         elif data['command'] == 'key':
#             self.common = self.private.gen_shared_key(data['content'])
#             add_key(self.destination, self.common)
#
#         elif data['command'] == 'salt':
#             self.salt = data['content']
#
#         elif data['command'] == 'login OK':
#             task.LoopingCall(self.process_command_queue).start(0.5)
#
#
# if packet['command'] == 'send' or packet['command'] == 'key':
#             try:
#                 self.factory.connections[packet['destination']].transport.write(json.dumps(packet).encode())
#             except builtins.KeyError:
#                 self.cache.append(packet)
#
#         elif packet['command'] == 'disconnect':
#             print(packet['username'] + " disconnected.")
#             del self.factory.connections[packet['username']]
#             self.transport.loseConnection()
#
#         elif packet['command'] == 'register':
#             password = b64decode(packet['password'])
#             salt = b64decode(packet['salt'])
#             pfp = b64decode(packet['pfp'])
#             add_user(packet['username'], password, salt)
#
#         elif packet['command'] == 'salt':
#             salt = get_salt_for_user(packet['username'])
#             if salt:
#                 packet = {
#                     'command': 'salt',
#                     'username': packet['username'],
#                     'content': salt
#                 }
#                 self.transport.write(json.dumps(packet).encode())
#
#         elif packet['command'] == 'login':
#             if login(packet['username'], b64decode(packet['password'].encode())):
#                 try:
#                     self.factory.connections[packet['username']]
#                 except KeyError:
#                     self.factory.connections[packet['username']] = self
#                 else:
#                     self.factory.connections[packet['username']].transport.loseConnection()
#                     self.factory.connections[packet['username']] = self
#                 print(packet['username'] + ' logged in')
#                 reply_packet = {'username': packet['username'], 'command': 'login OK'}
#                 self.transport.write(json.dumps(reply_packet).encode())
# def clear_cache(self):
#     for i in self.cache:
#         try:
#             self.factory.connections[i['destination']].transport.write(get_transportable_data())
#         except builtins.KeyError:
#             pass
#         else:
#             self.cache.remove(i)
