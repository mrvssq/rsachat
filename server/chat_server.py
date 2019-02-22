from threading import Thread
from Crypto.PublicKey import RSA
from Crypto import Random
import socket
import random
import json

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('', 8000))
server.listen(100)

list_clients = {}
newrooms = {'Room1': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
            'Room2': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
            'Room3': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
            'Room4': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
            'Room5': {'id': [], 'admin': 0, 'publicKeyROOM': 'key', 'requests': []}}

class MainBegin():
    def __init__(self, conn_sock):
        self.conn_sock = conn_sock
        self.id = self.gen_id()
        try:
            message_json = self.conn_sock.recv(2048)
            message = json.loads(message_json.decode('utf-8'))
            rooms = []
            if message['command'] == '-sFirstConnect':
                nickname = message['nickname']
                publicKeyClient = message['publicKey']
                check_valid_nickname = self.check_valid_nickname(nickname)
                if check_valid_nickname != '0':
                    nickname = self.random_nickname()
                list_clients[self.id] = {'socket': self.conn_sock, 'room': None, 'Public_Key': publicKeyClient,
                                         'nickname': nickname}
                [rooms.append(x) for x in newrooms.keys()]
                first_request = {'command': '-sFirstRequest',
                                'error': check_valid_nickname,
                                'nickname' : nickname,
                                'id': str(self.id),
                                'rooms': rooms,
                                'PublicKeyServer': str(gpublic),
                                'welcome': 'Welcome to this chat! Your id: ' + str(self.id)}

                send_one_client(first_request, self.id)
                list_clients[self.id]['Thread'] = WorkThreadClients(self.id, list_clients[self.id]['socket'])
                list_clients[self.id]['Thread'].start()
                print('new client :' + str(self.id) + ' connect to server in room: None')

        except Exception as error:
            print('error first_start:' + str(error))
            remove_con(self.id)

    def check_valid_nickname(self, nickname):
        forbidden_nicknames = ['', ' ', 'system']
        valid_symbol = ' 1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm!@#$%^&*()_+=-?/.,"][{}'
        check = '0'
        for id in list_clients.keys():
            if nickname == list_clients[id]['nickname']:
                check = 'error Nickname (With that Nickname already exists)'
        if nickname in forbidden_nicknames:
            check = 'error Nickname (Forbidden Nickname)'
        for n in nickname:
            if not (n in valid_symbol):
                check = 'error Nickname (In the Nickname there is a forbidden character)'
        if len(nickname) > 30:
            check = 'error Nickname (Length Nickname is too long)'
        if len(nickname) < 4:
            check = 'error Nickname (Length Nickname is too short)'
        return check

    def random_nickname(self):
        nickname = 'nick' + str(random.randint(10000, 99999))
        nicknames = []
        for id in list_clients.keys():
            nicknames.append(list_clients[id]['nickname'])
        while nickname in nicknames:
            nickname = 'nick' + str(random.randint(10000, 99999))
        return nickname

    def gen_id(self):
        len_id_from = 100000000
        len_id_before = 999999999
        iditem = random.randint(len_id_from, len_id_before)
        while iditem in list_clients.keys():
            iditem = random.randint(len_id_from, len_id_before)
        return iditem

class WorkThreadClients(Thread):
    def __init__(self, id, conn):
        Thread.__init__(self)
        self.id = id
        self.conn = conn
        self.private_key = RSA.importKey(gprivat)
    def run(self):
        while self.id in list_clients.keys():
            try:
                data_json = self.conn.recv(4096)
                if data_json:
                    commands = data_json[7:-5].split(b'}end}{begin{')
                    for command in commands:
                        command_right = self.command_handler(command)
                        comands_client(command_right, self.id, list_clients[self.id]['room'])
                else:
                    remove_con(self.id, list_clients[self.id]['room'])
            except:
                remove_con(self.id, list_clients[self.id]['room'])
        print('cycle "while" finished for client: ' + str(self.id))
        return None

    def command_handler(self, command):
        if command:
            command_with_json = b''
            blocks = command[11:-11].split(b'--[SPLIT]--')
            for block in blocks:
                command_with_json += self.private_key.decrypt(block)
            command_right = json.loads(command_with_json.decode('utf-8'))
            return command_right

def cryptoRSA(message_json, id):
    key_bytes = bytes(list_clients[id]['Public_Key'], "utf8")
    key = RSA.importKey(key_bytes)
    send_msg = b'{begin{--[SPLIT]--'
    if len(message_json) > 250:
        i = 0
        while len(message_json) > 250:
            enterMSG = message_json[:250]
            message_send = key.encrypt(bytes(enterMSG, "utf8"), random_generator)
            send_msg += message_send[0] + b'--[SPLIT]--'
            message_json = message_json[250:]
            i += 1
    message_send = key.encrypt(bytes(message_json, "utf8"), random_generator)
    send_msg += message_send[0] + b'--[SPLIT]--}end}'
    return send_msg

def send_one_client(message, id):
    try:
        message_json = json.dumps(message)
        send_msg = cryptoRSA(message_json, id)

        if len(send_msg) <= 4096:
            list_clients[id]['socket'].send(send_msg)
        else:
            print('len command have big size')
    except Exception as error:
        print('except error send one client:' + str(error))
        remove_con(id)

def broadcast(message, id, name_room=None):
    if name_room == None:
        for iditem in list_clients.keys():
            if list_clients[iditem]['room'] == None:
                if iditem != id:
                    send_one_client(message, iditem)
    else:
        for iditem in newrooms[name_room]['id']:
            if iditem != id:
                send_one_client(message, iditem)
    return None

def remove_con(id, name_room = None):
    try:
        if name_room == None:
            list_clients[id]['socket'].close()
            del list_clients[id]
        else:

            if id in newrooms[name_room]['id']:
                newrooms[name_room]['id'].remove(id)
            list_clients[id]['socket'].close()
            del list_clients[id]

            if newrooms[name_room]['id'] == []:
                del newrooms[name_room]
                refresh_rooms()
            else:
                if newrooms[name_room]['admin'] == id:
                    delegation_of_authority(name_room, id)
                refresh_clients(name_room)
    except:
        print('error remove client id: ' + str(id))
    return None

def comands_client(data, id, name_room):
    if data['command'] == '-sMsg':
        print(str(name_room) + '/' + str(id) + ': ' + data['message'])
        treatment_message(data, id, name_room)
    elif data['command'] == '-sOnline':
        print(str(id) + ': -sOnline')
        refresh_clients(name_room, id)
    elif data['command'] == '-sRooms':
        print(str(id) + ': -sRooms')
        refresh_rooms(id)
    elif data['command'] == '-sGo':
        print(str(id) + ': -sGo')
        request_generation(data, id)
    elif data['command'] == '-sResolutionAdmin':
        print(str(id) + ': -sResolutionAdmin')
        resolution_admin(data, name_room)
    elif data['command'] == '-sExitRoom':
        print(str(id) + ': -sExit room ' + name_room + ' client: ' + str(id))
        exit_room(id, name_room)
    elif data['command'] == '-sNewRoom':
        print(str(id) + ': -sNewRoom')
        create_new_room(data, id)
    elif data['command'] == '-sKickUser':
        print(str(id) + ': -sKickUser' + data['kick_id'])
        kick_user_from_room(data, id)
    else:
        print(str(id) + ': error command!:(' + data + ')')

def treatment_message(data, id, name_room):
    message = data['message']
    nick = list_clients[id]['nickname']
    send_data = {'command': '-sMsg', 'message': message, 'id': str(id), 'nickname': nick}
    broadcast(send_data, id, name_room)

def refresh_clients(name_room, id=0):
    users = newrooms[name_room]['id']
    send_data = {'command': '-sOnline', 'users': users}
    if id == 0:
        broadcast(send_data, 0, name_room)
    else:
        send_one_client(send_data, id)

def refresh_rooms(id=0):
    rooms = []
    [rooms.append(x) for x in newrooms.keys()]
    send_data = {'command': '-sRooms', 'rooms': rooms}
    if id == 0:
        broadcast(send_data, 0)
    else:
        send_one_client(send_data, id)

def request_generation(data, id):
    name_room = data['name_room']
    AdminRoom = newrooms[name_room]['admin']
    public_key = data['publicKey']
    try:
        if name_room in newrooms.keys():
            for room in newrooms.keys():
                if id in newrooms[room]['requests']:
                    newrooms[room]['requests'].remove(id)
                    request = newrooms[room]['requests']
                    admin = newrooms[room]['admin']
                    send_data_mini = {'command': '-sRefreshRequests', 'requests': request}
                    send_one_client(send_data_mini, admin)

            print('--begin_go_in_room-- id: ' + str(id))
            newrooms[name_room]['requests'].append(id)
            ids_request = newrooms[name_room]['requests']
            send_data = {'command': '-sResolutionAdmin', 'id': str(id),
                         'requests': ids_request, 'publicKey': str(public_key)}
            send_one_client(send_data, AdminRoom)
        else:
            error = {'command': '-sError', 'error': 'error Room does not exist'}
            send_one_client(error, id)
            print('-sGoRoom error: error Room does not exist')
    except:
        print('error go to room for id: ' + str(id) + ', in room: ' + name_room)
        remove_con(id, list_clients[id]['room'])

def resolution_admin(data, name_room):
    if data['response'] == 1:
        id_client = int(data['id'])
        CryptPrivatKeyRoom = data['cryptPrivatkey']
        if id_client in list_clients.keys():
            newrooms[name_room]['requests'].remove(id_client)
            newrooms[name_room]['id'].append(id_client)
            list_clients[id_client]['room'] = name_room
            send_data = {'command': '-sInvitationRoom', 'name_room': name_room, 'error': 0,
                         'CryptPrivatKeyRoom': CryptPrivatKeyRoom, 'welcome': 'Welcome to the room'}
            send_one_client(send_data, id_client)
            refresh_clients(name_room)
            print('--end_go_in_room-- id: ' + str(id_client))
        else:
            print('user not in server')
    else:
        print('error! Admin tell "NO"!')

def create_new_room(data, id):
    name_room = data['name_room']
    valid_name = check_valid_name_room(name_room)
    if list_clients[id]['room'] == None:
        if valid_name == 'ok':
            newrooms[name_room] = {'id': [id], 'admin': id, 'requests': []}
            list_clients[id]['room'] = name_room
            send_data = {'command': '-sNewRoom', 'error': '0', 'name_room': name_room}
            send_one_client(send_data, id)
            refresh_rooms()
            refresh_clients(name_room)
            print(str(id) + ' create new room: ' + str(name_room))
        else:
            error_create_new_room(valid_name, id)
    else:
        error = 'error you already make jokes in the room: ' + str(list_clients[id]['room'])
        error_create_new_room(error, id)

def check_valid_name_room(name_room):
    forbidden_name = ['', 'system', 'root', '-', ' ']
    valid_symbol = ' 1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm!@#$%^&*()_+=-?/.,"][{}'
    check = 'ok'
    if name_room in newrooms.keys():
        check = 'error Room with that name already exists'
    if name_room in forbidden_name:
        check = 'error name Room (forbidden name room)'
    for n in name_room:
        if not (n in valid_symbol):
            check = 'error name Room (In the name room there is a forbidden character)'
    if len(name_room) > 30:
        check = 'error name Room (Name is too long)'
    if len(name_room) < 4:
        check = 'error name Room (Name is too short)'
    return check

def error_create_new_room(error, id):
    print(error)
    command = {'command': '-sNewRoom', 'error': error}
    send_one_client(command, id)

def exit_room(id, name_room):
    if list_clients[id]['room'] == name_room:
        if id in newrooms[name_room]['id']:
            list_clients[id]['room'] = None
            newrooms[name_room]['id'].remove(id)
            clean_room(name_room, id)
            send_data = {'command': '-sExitRoom', 'indicator': 'exit', 'name': name_room}
            send_one_client(send_data, id)
        else:
            print('-sExitRoom error client ' + str(id) + ' not found')

def clean_room(name_room, id):
    if newrooms[name_room]['id'] == []:
        del newrooms[name_room]
        refresh_rooms()
    else:
        if newrooms[name_room]['admin'] == id:
            delegation_of_authority(name_room, id)
        refresh_clients(name_room)
        refresh_rooms(id)


def delegation_of_authority(name_room, id):
    try:
        if id in newrooms[name_room]['id']:
            newrooms[name_room]['id'].remove(id)
        lenght = len(newrooms[name_room]['id']) - 1
        randomid = random.randint(0, lenght)
        new_admin = newrooms[name_room]['id'][randomid]
        print('in room: ' + name_room + ', new admin: ' + str(new_admin))
        newrooms[name_room]['admin'] = new_admin
    except:
        print('error in delegation_of_authority')

def kick_user_from_room(data, id):
    name_room = list_clients[id]['room']
    id_kick = int(data['kick_id'])
    if (newrooms[name_room]['admin'] == id) and (id_kick != id):

        if id_kick in newrooms[name_room]['requests']:
            newrooms[name_room]['requests'].remove(id_kick)
        if id_kick in newrooms[name_room]['id']:
            newrooms[name_room]['id'].remove(id_kick)
            list_clients[id_kick]['room'] = None

            send_data = {'command': '-sExitRoom', 'indicator': 'kick', 'name': name_room}
            send_one_client(send_data, id_kick)

            refresh_clients(name_room)
            refresh_rooms(id_kick)

if __name__ == '__main__':
    random_generator = Random.new().read
    privatKey = RSA.generate(2048, random_generator)
    publicKey = privatKey.publickey()
    gpublic = publicKey.exportKey().decode('utf-8')
    gprivat = bytes(privatKey.exportKey())
    while True:
        conn_sock, addr = server.accept()
        MainBegin(conn_sock)
