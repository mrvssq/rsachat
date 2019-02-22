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
roms = {'Room1': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
        'Room2': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
        'Room3': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
        'Room4': {'id': [], 'admin': 123456, 'publicKeyROOM': 'key', 'requests': []},
        'Room5': {'id': [], 'admin': 0, 'publicKeyROOM': 'key', 'requests': []}}


def gen_id():
    len_id_from = 100000000
    len_id_before = 999999999
    iditem = random.randint(len_id_from, len_id_before)
    while iditem in list_clients.keys():
        iditem = random.randint(len_id_from, len_id_before)
    return iditem


class MainBegin:
    def __init__(self, connSock):
        self.conn_sock = connSock
        self.id = gen_id()
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
                [rooms.append(x) for x in roms.keys()]
                first_request = {'command': '-sFirstRequest',
                                 'error': check_valid_nickname,
                                 'nickname': nickname,
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

    @staticmethod
    def check_valid_nickname(nickname):
        forbidden_nicknames = ['', ' ', 'system']
        valid_symbol = ' 1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm!@#$%^&*()_+=-?/.,"][{}'
        check = '0'
        for id_client in list_clients.keys():
            if nickname == list_clients[id_client]['nickname']:
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

    @staticmethod
    def random_nickname():
        nickname = 'nick' + str(random.randint(10000, 99999))
        nicknames = []
        for id_client in list_clients.keys():
            nicknames.append(list_clients[id_client]['nickname'])
        while nickname in nicknames:
            nickname = 'nick' + str(random.randint(10000, 99999))
        return nickname


class WorkThreadClients(Thread):
    def __init__(self, id_client, conn):
        Thread.__init__(self)
        self.id = id_client
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


def cryptoRSA(message_json, id_client):
    key_bytes = bytes(list_clients[id_client]['Public_Key'], "utf8")
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


def send_one_client(message, id_client):
    try:
        message_json = json.dumps(message)
        send_msg = cryptoRSA(message_json, id_client)

        if len(send_msg) <= 4096:
            list_clients[id_client]['socket'].send(send_msg)
        else:
            print('len command have big size')
    except Exception as error:
        print('except error send one client:' + str(error))
        remove_con(id_client)


def broadcast(message, id_client, name_room=None):
    if name_room is None:
        for idItem in list_clients.keys():
            if list_clients[idItem]['room'] is None:
                if idItem != id_client:
                    send_one_client(message, idItem)
    else:
        for idItem in roms[name_room]['id']:
            if idItem != id_client:
                send_one_client(message, idItem)
    return None


def remove_con(id_client, name_room=None):
    try:
        if name_room is None:
            list_clients[id_client]['socket'].close()
            del list_clients[id_client]
        else:

            if id_client in roms[name_room]['id']:
                roms[name_room]['id'].remove(id_client)
            list_clients[id_client]['socket'].close()
            del list_clients[id_client]

            if not roms[name_room]['id']:
                del roms[name_room]
                refresh_rooms()
            else:
                if roms[name_room]['admin'] == id_client:
                    delegation_of_authority(name_room, id_client)
                refresh_clients(name_room)
    except:
        print('error remove client id: ' + str(id_client))
    return None


def comands_client(data, id_client, name_room):
    if data['command'] == '-sMsg':
        print(str(name_room) + '/' + str(id_client) + ': ' + data['message'])
        treatment_message(data, id_client, name_room)
    elif data['command'] == '-sOnline':
        print(str(id_client) + ': -sOnline')
        refresh_clients(name_room, id_client)
    elif data['command'] == '-sRooms':
        print(str(id_client) + ': -sRooms')
        refresh_rooms(id_client)
    elif data['command'] == '-sGo':
        print(str(id_client) + ': -sGo')
        request_generation(data, id_client)
    elif data['command'] == '-sResolutionAdmin':
        print(str(id_client) + ': -sResolutionAdmin')
        resolution_admin(data, name_room)
    elif data['command'] == '-sExitRoom':
        print(str(id_client) + ': -sExit room ' + name_room + ' client: ' + str(id_client))
        exit_room(id_client, name_room)
    elif data['command'] == '-sNewRoom':
        print(str(id_client) + ': -sNewRoom')
        create_new_room(data, id_client)
    elif data['command'] == '-sKickUser':
        print(str(id_client) + ': -sKickUser' + data['kick_id'])
        kick_user_from_room(data, id_client)
    else:
        print(str(id_client) + ': error command!:(' + data + ')')


def treatment_message(data, id_client, name_room):
    message = data['message']
    nick = list_clients[id_client]['nickname']
    send_data = {'command': '-sMsg', 'message': message, 'id': str(id_client), 'nickname': nick}
    broadcast(send_data, id_client, name_room)


def refresh_clients(name_room, id_client=0):
    users = roms[name_room]['id']
    send_data = {'command': '-sOnline', 'users': users}
    if id_client == 0:
        broadcast(send_data, 0, name_room)
    else:
        send_one_client(send_data, id_client)


def refresh_rooms(id_client=0):
    rooms = []
    [rooms.append(x) for x in roms.keys()]
    send_data = {'command': '-sRooms', 'rooms': rooms}
    if id_client == 0:
        broadcast(send_data, 0)
    else:
        send_one_client(send_data, id_client)


def request_generation(data, id_client):
    name_room = data['name_room']
    AdminRoom = roms[name_room]['admin']
    public_key = data['publicKey']
    try:
        if name_room in roms.keys():
            for room in roms.keys():
                if id_client in roms[room]['requests']:
                    roms[room]['requests'].remove(id_client)
                    request = roms[room]['requests']
                    admin = roms[room]['admin']
                    send_data_mini = {'command': '-sRefreshRequests', 'requests': request}
                    send_one_client(send_data_mini, admin)

            print('--begin_go_in_room-- id: ' + str(id_client))
            roms[name_room]['requests'].append(id_client)
            ids_request = roms[name_room]['requests']
            send_data = {'command': '-sResolutionAdmin', 'id': str(id_client),
                         'requests': ids_request, 'publicKey': str(public_key)}
            send_one_client(send_data, AdminRoom)
        else:
            error = {'command': '-sError', 'error': 'error Room does not exist'}
            send_one_client(error, id_client)
            print('-sGoRoom error: error Room does not exist')
    except:
        print('error go to room for id: ' + str(id_client) + ', in room: ' + name_room)
        remove_con(id_client, list_clients[id_client]['room'])


def resolution_admin(data, name_room):
    if data['response'] == 1:
        id_client = int(data['id'])
        CryptPrivatKeyRoom = data['cryptPrivatkey']
        if id_client in list_clients.keys():
            roms[name_room]['requests'].remove(id_client)
            roms[name_room]['id'].append(id_client)
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


def create_new_room(data, id_client):
    name_room = data['name_room']
    valid_name = check_valid_name_room(name_room)
    if list_clients[id_client]['room'] is None:
        if valid_name == 'ok':
            roms[name_room] = {'id': [id_client], 'admin': id_client, 'requests': []}
            list_clients[id_client]['room'] = name_room
            send_data = {'command': '-sNewRoom', 'error': '0', 'name_room': name_room}
            send_one_client(send_data, id_client)
            refresh_rooms()
            refresh_clients(name_room)
            print(str(id_client) + ' create new room: ' + str(name_room))
        else:
            error_create_new_room(valid_name, id_client)
    else:
        error = 'error you already make jokes in the room: ' + str(list_clients[id_client]['room'])
        error_create_new_room(error, id_client)


def check_valid_name_room(name_room):
    forbidden_name = ['', 'system', 'root', '-', ' ']
    valid_symbol = ' 1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm!@#$%^&*()_+=-?/.,"][{}'
    check = 'ok'
    if name_room in roms.keys():
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


def error_create_new_room(error, id_client):
    print(error)
    command = {'command': '-sNewRoom', 'error': error}
    send_one_client(command, id_client)


def exit_room(id_client, name_room):
    if list_clients[id_client]['room'] == name_room:
        if id_client in roms[name_room]['id']:
            list_clients[id_client]['room'] = None
            roms[name_room]['id'].remove(id_client)
            clean_room(name_room, id_client)
            send_data = {'command': '-sExitRoom', 'indicator': 'exit', 'name': name_room}
            send_one_client(send_data, id_client)
        else:
            print('-sExitRoom error client ' + str(id_client) + ' not found')


def clean_room(name_room, id_client):
    if not roms[name_room]['id']:
        del roms[name_room]
        refresh_rooms()
    else:
        if roms[name_room]['admin'] == id_client:
            delegation_of_authority(name_room, id_client)
        refresh_clients(name_room)
        refresh_rooms(id_client)


def delegation_of_authority(name_room, id_client):
    try:
        if id_client in roms[name_room]['id']:
            roms[name_room]['id'].remove(id_client)
        length = len(roms[name_room]['id']) - 1
        random_id = random.randint(0, length)
        new_admin = roms[name_room]['id'][random_id]
        print('in room: ' + name_room + ', new admin: ' + str(new_admin))
        roms[name_room]['admin'] = new_admin
    except:
        print('error in delegation_of_authority')


def kick_user_from_room(data, id_client):
    name_room = list_clients[id_client]['room']
    id_kick = int(data['kick_id'])
    if (roms[name_room]['admin'] == id_client) and (id_kick != id_client):

        if id_kick in roms[name_room]['requests']:
            roms[name_room]['requests'].remove(id_kick)
        if id_kick in roms[name_room]['id']:
            roms[name_room]['id'].remove(id_kick)
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
