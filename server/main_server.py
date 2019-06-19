from threading import Thread
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import random
import socket
import random
import json

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('', 8000))
server.listen(100)

globalRoom = 'root'

dictClients = {}
dictRooms = {globalRoom: {'admin': None, 'users': [], 'requests': []}}


def genRandomID(fromINT, beforeINT):
    idUser = random.randint(fromINT, beforeINT)
    while idUser in dictClients.keys():
        idUser = random.randint(fromINT, beforeINT)
    return idUser


def genRandomNickname(fromINT, beforeINT):
    nick = 'nick' + str(random.randint(fromINT, beforeINT))
    nicknames = [dictClients[clientID]['nickname'] for clientID in dictClients.keys()]
    while nick in nicknames:
        nick = 'nick' + str(random.randint(fromINT, beforeINT))
    return nick


def checkValidSymbol(name):
    forbiddenName = ['', ' ', 'system', 'admin', globalRoom, 'create new room', 'None']
    validSymbol = '1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm!@#$%^&*()_+=-?/.,"][{}'
    check = 1
    if name in forbiddenName:
        check = 2
    if [i for i in name if not (i in validSymbol)]:
        check = 3
    if len(name) > 30:
        check = 4
    if len(name) < 4:
        check = 5
    return check


def checkValidNickname(nickname):
    check = {'state': False, 'msg': 'error Unknown error'}
    if checkValidSymbol(nickname) == 1:
        check = {'state': True, 'msg': 'valid nickname'}
    else:
        if checkValidSymbol(nickname) == 2:
            check = {'state': False, 'msg': 'error Nickname (Forbidden Nickname)'}
        if checkValidSymbol(nickname) == 3:
            check = {'state': False, 'msg': 'error Nickname (In the Nickname there is a forbidden character)'}
        if checkValidSymbol(nickname) == 4:
            check = {'state': False, 'msg': 'error Nickname (Length Nickname is too long)'}
        if checkValidSymbol(nickname) == 5:
            check = {'state': False, 'msg': 'error Nickname (Length Nickname is too short)'}
    if nickname in [dictClients[client]['nickname'] for client in dictClients.keys()]:
        check = {'state': False, 'msg': 'error Nickname (With that Nickname already exists)'}
    return check


def checkValidNameRoom(nameRoom):
    check = {'state': False, 'msg': 'error Unknown error'}
    if checkValidSymbol(nameRoom) == 1:
        check = {'state': True, 'msg': 'valid nickname'}
    else:
        if checkValidSymbol(nameRoom) == 2:
            check = {'state': False, 'msg': 'name Room (forbidden name room)'}
        if checkValidSymbol(nameRoom) == 3:
            check = {'state': False, 'msg': 'name Room (In the name room there is a forbidden character)'}
        if checkValidSymbol(nameRoom) == 4:
            check = {'state': False, 'msg': 'name Room (Name is too long)'}
        if checkValidSymbol(nameRoom) == 5:
            check = {'state': False, 'msg': 'name Room (Name is too short)'}
    if nameRoom in dictRooms.keys():
        check = {'state': False, 'msg': 'error Room with that name already exists'}
    return check


class MainBegin:
    def __init__(self, connSock):
        self.connSocket = connSock
        self.id = genRandomID(100000000, 999999999)
        try:
            messageJson = self.connSocket.recv(2048)
            message = json.loads(messageJson.decode('utf-8'))
            if message['command'] == '-sFirstConnect':
                nickname = message['nickname']
                publicKeyClient = message['publicKey']
                checkNickname = checkValidNickname(nickname)
                if not checkNickname['state']:
                    nickname = genRandomNickname(10000, 99999)
                dictClients[self.id] = {'socket': self.connSocket, 'Public_Key': publicKeyClient,
                                        'nickname': nickname}
                firstRequest = {'command': '-sFirstRequest',
                                'error': checkNickname['msg'],
                                'nickname': nickname,
                                'id': str(self.id),
                                'rooms': [room for room in dictRooms.keys()],
                                'PublicKeyServer': str(globalPublic),
                                'welcome': 'Welcome to this chat! Your id: ' + str(self.id),
                                'room': globalRoom}

                sendOneClientMessage(firstRequest, self.id)
                dictRooms[globalRoom]['users'].append(self.id)
                refreshClients(globalRoom)
                dictClients[self.id]['Thread'] = WorkThreadClients(self.id, dictClients[self.id]['socket'])
                dictClients[self.id]['Thread'].start()
                print('new client :' + str(self.id) + ' connect to server in room: root')
        except Exception as error:
            excaptionWrite(error, self.id)
            removeSocketCompletely(self.id)


class WorkThreadClients(Thread):
    def __init__(self, clientID, socketClient):
        Thread.__init__(self)
        self.id = clientID
        self.socketClient = socketClient
        self.privateKey = RSA.importKey(globalPrivate)

    def run(self):
        while self.id in dictClients.keys():
            try:
                dataJson = self.socketClient.recv(4096)
                if dataJson:
                    commands = dataJson[7:-5].split(b'}end}{begin{')
                    for command in commands:
                        commandRight = self.commandHandler(command)
                        comandsHandler(commandRight, self.id)
                else:
                    removeSocketCompletely(self.id)
            except Exception as error:
                excaptionWrite(error, self.id)
                removeSocketCompletely(self.id)
        print('cycle "while" finished for client: ' + str(self.id))
        return None

    def commandHandler(self, command):
        try:
            if command:
                commandWithJson = b''
                blocks = command[11:-11].split(b'--[SPLIT]--')
                for block in blocks:
                    commandWithJson += self.privateKey.decrypt(block)
                commandRight = json.loads(commandWithJson.decode('utf-8'))
                return commandRight
        except Exception as error:
            excaptionWrite(error, self.id)
            removeSocketCompletely(self.id)
            return {'room': None, 'error': 'commandHandler'}


def cryptoRSA(messageJson, clientID):
    try:
        keyBytes = bytes(dictClients[clientID]['Public_Key'], "utf8")
        key = RSA.importKey(keyBytes)
        sendMsg = b'{begin{--[SPLIT]--'
        if len(messageJson) > 250:
            i = 0
            while len(messageJson) > 250:
                enterMSG = messageJson[:250]
                messageSend = key.encrypt(bytes(enterMSG, "utf8"), randomGenerator)
                sendMsg += messageSend[0] + b'--[SPLIT]--'
                messageJson = messageJson[250:]
                i += 1
        messageSend = key.encrypt(bytes(messageJson, "utf8"), randomGenerator)
        sendMsg += messageSend[0] + b'--[SPLIT]--}end}'
        return sendMsg
    except Exception as error:
        excaptionWrite(error, clientID)
        return 'error cryptoRSA'


def sendOneClientMessage(message, clientID):
    try:
        messageJson = json.dumps(message)
        sendMsg = cryptoRSA(messageJson, clientID)
        if len(sendMsg) <= 4096:
            dictClients[clientID]['socket'].send(sendMsg)
        else:
            print('len command have big size')
    except Exception as error:
        excaptionWrite(error, clientID)
        removeSocketCompletely(clientID)
    return None


def broadcastMessage(message, outcastClientID=None, nameRoom=None):
    try:
        if nameRoom is None:
            users = dictClients.keys()
        else:
            users = dictRooms[nameRoom]['users']
        for client in users:
            if client != outcastClientID:
                sendOneClientMessage(message, client)
    except Exception as error:
        excaptionWrite(error, outcastClientID, nameRoom)
    return None


def setRoomRight(clientID, nameRoom, right, color, welcome, key=None):
    try:
        sendData = {'command': '-sSetRoomRight', 'room': nameRoom, 'right': right,
                    'welcome': welcome, 'color': color, 'CryptPrivatKeyRoom': key}
        sendOneClientMessage(sendData, clientID)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def writeInLogClient(text, clientID, typeColor, nameRoom):
    try:
        sendData = {'command': '-sError', 'type': typeColor,
                    'text': text, 'room': nameRoom, 'address': None}
        sendOneClientMessage(sendData, clientID)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def comandsHandler(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        command = data['command']
        print('\t' + str(clientID) + ' sent command: ' + command)

        if command == '-sMsg':
            processingMessage(data, clientID)
        elif command == '-sOnline':
            refreshClients(nameRoom, clientID)
        elif command == '-sRooms':
            refreshRooms(clientID)
        elif command == '-sGo':
            requestGenerationRoom(data, clientID)
        elif command == '-sResolutionAdmin':
            resolutionAdminRoom(data, clientID)
        elif command == '-sExitRoom':
            exitRoom(nameRoom, clientID)
        elif command == '-sNewRoom':
            createNewRoom(data, clientID)
        elif command == '-sKickUser':
            kickUserOutRoom(data, clientID)
        elif command == '-sSetKeyAES':
            sendKeyAES(data, clientID)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
        removeSocketCompletely(clientID)


def processingMessage(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        message = data['message']
        nick = dictClients[clientID]['nickname']
        if clientID in dictRooms[nameRoom]['users']:
            sendData = {'command': '-sMsg', 'message': message, 'id': str(clientID), 'nickname': nick, 'room': nameRoom}
            broadcastMessage(sendData, clientID, nameRoom)
            print(nameRoom + '/' + str(clientID) + ': ' + message)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def refreshClients(nameRoom, clientID=None):
    try:
        if clientID in dictRooms[nameRoom]['users'] or clientID is None:
            users = {}
            requests = {}
            admin = dictRooms[nameRoom]['admin']
            if nameRoom in dictRooms.keys():
                for usr in dictRooms[nameRoom]['users']:
                    users[usr] = dictClients[usr]['Public_Key']
                for req in dictRooms[nameRoom]['requests']:
                    requests[req] = dictClients[req]['Public_Key']
                sendData = {'command': '-sRefreshUsers', 'users': users, 'admin': admin,
                            'requests': requests, 'room': nameRoom}
                if clientID is None:
                    broadcastMessage(sendData, clientID, nameRoom)
                else:
                    sendOneClientMessage(sendData, clientID)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def refreshRooms(clientID=None):
    try:
        rooms = [room for room in dictRooms.keys()]
        sendData = {'command': '-sRooms', 'rooms': rooms}
        if clientID is None:
            broadcastMessage(sendData)
        else:
            sendOneClientMessage(sendData, clientID)
    except Exception as error:
        excaptionWrite(error, clientID)
    return None


def requestGenerationRoom(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        if nameRoom in dictRooms:
            if clientID not in dictRooms[nameRoom]['users'] and clientID not in dictRooms[nameRoom]['requests']:
                adminRoom = dictRooms[nameRoom]['admin']
                if adminRoom is None or adminRoom not in dictClients.keys():
                    dictRooms[nameRoom]['users'].append(clientID)
                    if nameRoom != globalRoom:
                        dictRooms[nameRoom]['admin'] = clientID
                        welcome = 'Welcome to the room. You are admin'
                        right = 3
                    else:
                        welcome = 'Welcome to the room'
                        right = 2
                    setRoomRight(clientID, nameRoom, right, 'green', welcome)
                else:
                    print('--begin_go_in_room-- id: ' + str(clientID))
                    dictRooms[nameRoom]['requests'].append(clientID)
                refreshClients(nameRoom)
        else:
            writeInLogClient('error. Room does not exist', clientID, 'red', nameRoom)
            print('-sGo: error Room does not exist')
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
        removeSocketCompletely(clientID)
    return None


def resolutionAdminRoom(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        if clientID == dictRooms[nameRoom]['admin']:
            if data['response'] == 1:
                approvedID = int(data['id'])
                if approvedID in dictClients.keys():
                    dictRooms[nameRoom]['requests'].remove(approvedID)
                    dictRooms[nameRoom]['users'].append(approvedID)
                    welcome = 'Welcome to the room'
                    setRoomRight(approvedID, nameRoom, 2, 'green', welcome, data['cryptPrivatkey'])
                    refreshClients(nameRoom)
                    print('--end_go_in_room-- id: ' + str(approvedID))
                else:
                    print('user ' + str(approvedID) + ' not in server')
            else:
                print('error! Admin tell "NO"!')
        else:
            print('error! ' + str(clientID) + ' not Admin!')
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def exitRoom(nameRoom, clientID):
    try:
        if clientID in dictRooms[nameRoom]['users']:
            removeUserFromRoom(nameRoom, clientID)
            welcome = 'You left the room'
            setRoomRight(clientID, nameRoom, 0, 'purple', welcome)
            print(str(clientID) + ': -sExit room ' + nameRoom)
        elif clientID in dictRooms[nameRoom]['requests']:
            dictRooms[nameRoom]['requests'].remove(clientID)
            welcome = 'You canceled request'
            setRoomRight(clientID, nameRoom, 0, 'purple', welcome)
            refreshClients(nameRoom)
            print(str(clientID) + ': -sExit room ' + nameRoom)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def removeUserFromRoom(nameRoom, clientID):
    try:
        dictRooms[nameRoom]['users'].remove(clientID)
        if dictRooms[nameRoom]['admin'] == clientID:
            if not dictRooms[nameRoom]['users']:
                dictRooms[nameRoom]['admin'] = None
                for req in dictRooms[nameRoom]['requests']:
                    exitRoom(nameRoom, req)
            else:
                newAdmin = dictRooms[nameRoom]['users'][0]
                dictRooms[nameRoom]['admin'] = newAdmin
                welcome = 'You new admin this room'
                setRoomRight(newAdmin, nameRoom, 3, 'green', welcome)
        refreshClients(nameRoom)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def createNewRoom(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        validName = checkValidNameRoom(nameRoom)
        if validName['state']:
            dictRooms[nameRoom] = {'admin': clientID, 'users': [clientID], 'requests': []}
            sendData = {'command': '-sNewRoom', 'room': nameRoom}
            sendOneClientMessage(sendData, clientID)
            refreshRooms()
            refreshClients(nameRoom, clientID)
            print(str(clientID) + ' create new room: ' + nameRoom)
        else:
            writeInLogClient(validName['msg'], clientID, 'purple', nameRoom)
            print(str(clientID) + ': -sNewRoom error: ' + validName['msg'])
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def kickUserOutRoom(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        kickId = int(data['kick_id'])
        if (dictRooms[nameRoom]['admin'] == clientID)\
                and (kickId != clientID)\
                and (kickId in dictRooms[nameRoom]['users']):
            dictRooms[nameRoom]['users'].remove(kickId)
            welcome = 'You kicked out of the room'
            setRoomRight(kickId, nameRoom, 0, 'red', welcome)
            refreshClients(nameRoom)
            print(str(clientID) + ': -sKickUser. kick user:' + str(kickId))
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def sendKeyAES(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        if clientID == dictRooms[nameRoom]['admin']:
            key = data['keyAES']
            print('nameRoom: ' + nameRoom + ', new keyAES: ' + key)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def removeSocketCompletely(clientID):
    try:
        cleanAllRequestsClient(clientID)
        cleanAllRoomClient(clientID)
        dictClients[clientID]['socket'].close()
        del dictClients[clientID]
    except Exception as error:
        excaptionWrite(error, clientID)
    return None


def cleanAllRequestsClient(clientID):
    try:
        requestsThisClient = [room for room in dictRooms.keys() if clientID in dictRooms[room]['requests']]
        for room in requestsThisClient:
            dictRooms[room]['requests'].remove(clientID)
            refreshClients(room)
    except Exception as error:
        excaptionWrite(error, clientID)
    return None


def cleanAllRoomClient(clientID):
    try:
        roomsThisClient = [room for room in dictRooms.keys() if clientID in dictRooms[room]['users']]
        for room in roomsThisClient:
            removeUserFromRoom(room, clientID)
    except Exception as error:
        excaptionWrite(error, clientID)
    return None


def excaptionWrite(errorTry, ClientID, nameRoom=None):
    import inspect
    nameFun = inspect.stack()[1][3]
    print('ERROR try in ' + str(nameFun) + 'c[' + str(ClientID) +
          '], r[' + str(nameRoom) + ']: ' + str(errorTry))
    return None


if __name__ == '__main__':
    randomGenerator = Random.new().read
    privateKey = RSA.generate(2048, randomGenerator)
    publicKey = privateKey.publickey()
    globalPublic = publicKey.exportKey().decode('utf-8')
    globalPrivate = bytes(privateKey.exportKey())
    while True:
        connSocket, addr = server.accept()
        MainBegin(connSocket)
