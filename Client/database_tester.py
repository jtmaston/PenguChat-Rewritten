from Client.DBHandler import *

query = Messages.select()

for i in query:
    print(i.__dict__)