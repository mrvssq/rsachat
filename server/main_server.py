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

dictClients = {}
dictRooms = {}


def genRandomID(fromINT=100000000, beforeINT=999999999):
    idUser = random.randint(fromINT, beforeINT)
    while idUser in dictClients.keys():
        idUser = random.randint(fromINT, beforeINT)
    return idUser


def genRandomNickname(fromINT=10000, beforeINT=99999):
    nick = 'nick' + str(random.randint(fromINT, beforeINT))
    nicknames = [dictClients[clientID]['nickname'] for clientID in dictClients.keys()]
    while nick in nicknames:
        nick = 'nick' + str(random.randint(fromINT, beforeINT))
    return nick


def checkValidNickname(nickname):
    forbiddenNicknames = ['', ' ', 'system', 'admin', 'root']
    validSymbol = ' 1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm!@#$%^&*()_+=-?/.,"][{}'
    check = {'state': True, 'msg': 'valid nickname'}

    for nicknameExist in [dictClients[client]['nickname'] for client in dictClients.keys()]:
        if nickname == nicknameExist:
            check = {'state': False, 'msg': 'error Nickname (With that Nickname already exists)'}
    if nickname in forbiddenNicknames:
        check = {'state': False, 'msg': 'error Nickname (Forbidden Nickname)'}
    if [i for i in nickname if not (i in validSymbol)]:
        check = {'state': False, 'msg': 'error Nickname (In the Nickname there is a forbidden character)'}
    if len(nickname) > 30:
        check = {'state': False, 'msg': 'error Nickname (Length Nickname is too long)'}
    if len(nickname) < 4:
        check = {'state': False, 'msg': 'error Nickname (Length Nickname is too short)'}
    return check


def checkValidNameRoom(nameRoom):
    forbiddenName = ['', ' ', 'system', 'admin', 'root', '-']
    validSymbol = ' 1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm!@#$%^&*()_+=-?/.,"][{}'
    check = {'state': True, 'msg': 'valid room name'}

    for nameRoomExist in [room for room in dictRooms.keys()]:
        if nameRoom == nameRoomExist:
            check = {'state': False, 'msg': 'error Room with that name already exists'}
    if nameRoom in forbiddenName:
        check = {'state': False, 'msg': 'error name Room (forbidden name room)'}
    if [i for i in nameRoom if not (i in validSymbol)]:
        check = {'state': False, 'msg': 'error name Room (In the name room there is a forbidden character)'}
    if len(nameRoom) > 30:
        check = {'state': False, 'msg': 'error name Room (Name is too long)'}
    if len(nameRoom) < 4:
        check = {'state': False, 'msg': 'error name Room (Name is too short)'}
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
                if checkNickname['state']:
                    nickname = genRandomNickname(10000, 99999)
                dictClients[self.id] = {'socket': self.connSocket, 'room': None, 'Public_Key': publicKeyClient,
                                        'nickname': nickname}
                firstRequest = {'command': '-sFirstRequest',
                                'error': checkNickname['msg'],
                                'nickname': nickname,
                                'id': str(self.id),
                                'rooms': [room for room in dictRooms.keys()],
                                'PublicKeyServer': str(globalPublic),
                                'welcome': 'Welcome to this chat! Your id: ' + str(self.id)}

                sendOneClientMessage(firstRequest, self.id)
                dictClients[self.id]['Thread'] = WorkThreadClients(self.id, dictClients[self.id]['socket'])
                dictClients[self.id]['Thread'].start()
                print('new client :' + str(self.id) + ' connect to server in room: None')

        except Exception as error:
            print('error first_start:' + str(error))
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
                        comandsHandler(commandRight, self.id, dictClients[self.id]['room'])
                else:
                    removeSocketCompletely(self.id)
            except Exception as error:
                print('error: ' + str(error))
                removeSocketCompletely(self.id)
        print('cycle "while" finished for client: ' + str(self.id))
        return None

    def commandHandler(self, command):
        if command:
            commandWithJson = b''
            blocks = command[11:-11].split(b'--[SPLIT]--')
            for block in blocks:
                commandWithJson += self.privateKey.decrypt(block)
            commandRight = json.loads(commandWithJson.decode('utf-8'))
            return commandRight


def comandsHandler(data, clientID, nameRoom):
    if data['command'] == '-sMsg':
        print(str(nameRoom) + '/' + str(clientID) + ': ' + data['message'])
        processingMessage(data, clientID, nameRoom)
    elif data['command'] == '-sOnline':
        print(str(clientID) + ': -sOnline')
        refreshClients(nameRoom, clientID)
    elif data['command'] == '-sRooms':
        print(str(clientID) + ': -sRooms')
        refreshRooms(clientID)
    elif data['command'] == '-sGo':
        print(str(clientID) + ': -sGo')
        requestGenerationRoom(data, clientID)
    elif data['command'] == '-sResolutionAdmin':
        print(str(clientID) + ': -sResolutionAdmin')
        resolutionAdminRoom(data, nameRoom)
    elif data['command'] == '-sExitRoom':
        print(str(clientID) + ': -sExit room ' + nameRoom + ' client: ' + str(clientID))
        exitRoom(clientID, nameRoom)
    elif data['command'] == '-sNewRoom':
        print(str(clientID) + ': -sNewRoom')
        createNewRoom(data, clientID)
    elif data['command'] == '-sKickUser':
        print(str(clientID) + ': -sKickUser. kick user:' + data['kick_id'])
        kickUserOutRoom(data, clientID)
    else:
        print(str(clientID) + ': error command!:(' + data + ')')


def processingMessage(data, clientID, nameRoom):
    message = data['message']
    nick = dictClients[clientID]['nickname']
    sendData = {'command': '-sMsg', 'message': message, 'id': str(clientID), 'nickname': nick}
    broadcastMessage(sendData, clientID, nameRoom)


def refreshClients(nameRoom, clientID=0):
    clientsThisRoom = [client for client in dictClients.keys() if dictClients[client]['room'] == nameRoom]
    sendData = {'command': '-sOnline', 'users': clientsThisRoom}
    if clientID == 0:
        broadcastMessage(sendData, 0, nameRoom)
    else:
        sendOneClientMessage(sendData, clientID)


def refreshRooms(clientID=0):
    sendData = {'command': '-sRooms', 'rooms': [room for room in dictRooms.keys()]}
    if clientID == 0:
        broadcastMessage(sendData, 0)
    else:
        sendOneClientMessage(sendData, clientID)


def requestGenerationRoom(data, clientID):
    nameRoom = data['name_room']
    pubKey = data['publicKey']
    try:
        adminRoom = dictRooms[nameRoom]['admin']
        if adminRoom is not None:
            if clientID not in dictRooms[nameRoom]['requests']:
                for room in [r for r in dictRooms.keys() if r != nameRoom]:
                    if clientID in dictRooms[room]['requests']:
                        dictRooms[room]['requests'].remove(clientID)
                        sendDataUpdate = {'command': '-sRefreshRequests', 'requests': dictRooms[room]['requests']}
                        sendOneClientMessage(sendDataUpdate, dictRooms[room]['admin'])
                print('--begin_go_in_room-- id: ' + str(clientID))
                dictRooms[nameRoom]['requests'].append(clientID)
                sendData = {'command': '-sResolutionAdmin', 'id': str(clientID),
                            'requests': dictRooms[nameRoom]['requests'], 'publicKey': str(pubKey)}
                sendOneClientMessage(sendData, adminRoom)
        else:
            error = {'command': '-sError', 'type': 'none', 'error': 'error Room does not exist'}
            sendOneClientMessage(error, clientID)
            print('-sGoRoom error: error Room does not exist')
    except Exception as error:
        print('error go to room for id: ' + str(clientID) + ', in room: ' + nameRoom + '. Error: ' + str(error))
        removeSocketCompletely(clientID)


def resolutionAdminRoom(data, nameRoom):
    if data['response'] == 1:
        clientID = int(data['id'])
        CryptPrivatKeyRoom = data['cryptPrivatkey']
        if clientID in dictClients.keys():
            dictRooms[nameRoom]['requests'].remove(clientID)
            dictClients[clientID]['room'] = nameRoom
            sendData = {'command': '-sInvitationRoom', 'name_room': nameRoom, 'error': 0,
                        'CryptPrivatKeyRoom': CryptPrivatKeyRoom, 'welcome': 'Welcome to the room'}
            sendOneClientMessage(sendData, clientID)
            refreshClients(nameRoom)
            print('--end_go_in_room-- id: ' + str(clientID))
        else:
            print('user not in server')
    else:
        print('error! Admin tell "NO"!')


def createNewRoom(data, clientID):
    nameRoom = data['name_room']
    validName = checkValidNameRoom(nameRoom)
    if dictClients[clientID]['room'] is None:
        if validName['state']:
            dictRooms[nameRoom] = {'admin': clientID, 'requests': []}
            dictClients[clientID]['room'] = nameRoom
            sendData = {'command': '-sNewRoom', 'error': 'valid room name', 'name_room': nameRoom}
            sendOneClientMessage(sendData, clientID)
            refreshRooms()
            refreshClients(nameRoom)
            print(str(clientID) + ' create new room: ' + nameRoom)
        else:
            command = {'command': '-sNewRoom', 'error': validName['msg']}
            sendOneClientMessage(command, clientID)
    else:
        error = 'error. You are already in room: ' + dictClients[clientID]['room']
        command = {'command': '-sNewRoom', 'error': error}
        sendOneClientMessage(command, clientID)


def exitRoom(clientID, nameRoom):
    if dictClients[clientID]['room'] == nameRoom:
        cleanRoom(nameRoom, clientID)
        sendData = {'command': '-sExitRoom', 'indicator': 'exit', 'name': nameRoom}
        sendOneClientMessage(sendData, clientID)


def cleanRoom(nameRoom, clientID):
    clientsThisRoom = [client for client in dictClients.keys() if dictClients[client]['room'] == nameRoom]
    if [clientID] == clientsThisRoom:
        dictClients[clientID]['room'] = None
        del dictRooms[nameRoom]
        refreshRooms()
    else:
        if dictRooms[nameRoom]['admin'] == clientID:
            delegationOfAuthority(nameRoom, clientID)
        dictClients[clientID]['room'] = None
        refreshClients(nameRoom)
        refreshRooms(clientID)


def cleanAllRequestsClient(clientID):
    requestsThisRoom = [room for room in dictRooms.keys() if dictRooms[room]['requests'] == clientID]
    for room in requestsThisRoom:
        dictRooms[room]['requests'].remove(clientID)


def delegationOfAuthority(nameRoom, adminID):
    try:
        clientsIDThisRoom = [client for client in dictClients.keys()
                             if (dictClients[client]['room'] == nameRoom) and client != adminID]
        newAdmin = Random.random.choice(clientsIDThisRoom)
        dictRooms[nameRoom]['admin'] = newAdmin
        print('in room: ' + nameRoom + ', new admin: ' + str(newAdmin))
    except Exception as error:
        print('error in delegation_of_authority. Error: ' + str(error))


def kickUserOutRoom(data, clientID):
    nameRoom = dictClients[clientID]['room']
    kickId = int(data['kick_id'])
    if (dictRooms[nameRoom]['admin'] == clientID) and (kickId != clientID):
        dictClients[kickId]['room'] = None
        sendData = {'command': '-sExitRoom', 'indicator': 'kick', 'name': nameRoom}
        sendOneClientMessage(sendData, kickId)
        refreshClients(nameRoom)
        refreshRooms(kickId)


def cryptoRSA(messageJson, clientID):
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


def sendOneClientMessage(message, clientID):
    try:
        messageJson = json.dumps(message)
        sendMsg = cryptoRSA(messageJson, clientID)
        if len(sendMsg) <= 4096:
            dictClients[clientID]['socket'].send(sendMsg)
        else:
            print('len command have big size')
    except Exception as error:
        print('except error send one client:' + str(error))
        removeSocketCompletely(clientID)


def broadcastMessage(message, clientID, nameRoom=None):
    clientsThisRoom = [client for client in dictClients.keys() if dictClients[client]['room'] == nameRoom]
    for client in clientsThisRoom:
        if client != clientID:
            sendOneClientMessage(message, client)
    return None


def removeSocketCompletely(clientID):
    try:
        nameRoom = dictClients[clientID]['room']
        cleanAllRequestsClient(clientID)
        if nameRoom is not None:
            cleanRoom(nameRoom, clientID)
        dictClients[clientID]['socket'].close()
        del dictClients[clientID]
    except Exception as error:
        print('error remove client id: ' + str(clientID) + '. Error: ' + str(error))
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
