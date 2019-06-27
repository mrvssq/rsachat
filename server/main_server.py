from threading import Thread
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
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
            if self.connSocket == 'fake':
                nickname = genRandomNickname(10000, 99999)
                dictClients[self.id] = {'socket': None, 'Public_Key': str(globalPublic),
                                        'nickname': nickname}
                dictRooms['BigSizeRoom']['users'].append(self.id)
            else:
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
                    writeInConsole('open connection', 'new client :'
                                   + str(self.id) + ' connect to server in room: root')
        except Exception as error:
            excaptionWrite(error, self.id)
            removeSocketCompletely(self.id)


class WorkThreadClients(Thread):
    def __init__(self, clientID, socketClient):
        Thread.__init__(self)
        self.id = clientID
        self.socketClient = socketClient
        self.serverCipherRSA = PKCS1_OAEP.new(RSA.importKey(globalPrivate))

    def run(self):
        stackPackets = b''
        while self.id in dictClients.keys():
            packNow = None
            try:
                dataJson = self.socketClient.recv(4096)
                if dataJson:
                    stackPackets += dataJson
                    if stackPackets.decode('utf-8')[0] == '[':
                        if stackPackets.decode('utf-8')[-1] == '+':
                            packetsList = stackPackets.split(b'+')
                            for pack in packetsList:
                                if pack != b'':
                                    packNow = pack
                                    encPack = json.loads(pack.decode('utf-8'))
                                    data = self.decodePacket(encPack)
                                    if data is not None:
                                        comandsHandlerServer(data, self.id)
                            stackPackets = b''
                else:
                    removeSocketCompletely(self.id)
            except json.decoder.JSONDecodeError as error:
                writeInConsole('bad packet', str(packNow))
                excaptionWrite(error, self.id)
            except Exception as error:
                excaptionWrite(error, self.id)
                removeSocketCompletely(self.id)
        writeInConsole('connection closed', 'cycle "while" finished for client: ' + str(self.id))
        return None

    def decodePacket(self, pak):
        try:
            encSessionKey = bytes.fromhex(pak[0])
            nonce = bytes.fromhex(pak[1])
            cipherText = bytes.fromhex(pak[2])
            tag = bytes.fromhex(pak[3])

            sessionKey = self.serverCipherRSA.decrypt(encSessionKey)
            cipherAES = AES.new(sessionKey, AES.MODE_EAX, nonce)
            dataDump = cipherAES.decrypt_and_verify(cipherText, tag)
            data = json.loads(dataDump.decode('utf-8'))
            return data
        except Exception as error:
            excaptionWrite(error, self.id)
            return None


def cryptoRSA(text, key):
    try:
        publicKeyRSA = RSA.importKey(bytes(key, "utf8"))
        cipherRSA = PKCS1_OAEP.new(publicKeyRSA)

        sessionKey = get_random_bytes(16)
        encSessionKey = cipherRSA.encrypt(sessionKey)

        cipherAES = AES.new(sessionKey, AES.MODE_EAX)
        cipherText, tag = cipherAES.encrypt_and_digest(text.encode('utf-8'))

        packet = [encSessionKey.hex(),
                  cipherAES.nonce.hex(),
                  cipherText.hex(),
                  tag.hex()]
        packetDumps = json.dumps(packet)
        return packetDumps
    except Exception as error:
        excaptionWrite(error, 0)
        return None


def sendOneClientMessage(message, clientID):
    import time
    try:
        if dictClients[clientID]['socket'] is not None:
            messageJson = json.dumps(message)
            packet = cryptoRSA(messageJson, dictClients[clientID]['Public_Key'])
            if len(packet) < 4096:
                time.sleep(0.01)
                dictClients[clientID]['socket'].send(packet.encode('utf-8') + b'+')
            else:
                writeInConsole('error', 'Len command have BIG size, idClient: ' + str(clientID))
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


def comandsHandlerServer(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        command = data['command']
        writeInConsole('\t' + str(clientID) + ' sent command', command)

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
        elif command == '-sGetRSAKeyClient':
            setRSAKeyClient(data['user'], clientID)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
        removeSocketCompletely(clientID)


def processingMessage(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        message = data['message']
        encrypt = data['encrypt']
        nick = dictClients[clientID]['nickname']
        if clientID in dictRooms[nameRoom]['users']:
            sendData = {'command': '-sMsg', 'message': message, 'id': str(clientID), 'nickname': nick, 'room': nameRoom}
            broadcastMessage(sendData, clientID, nameRoom)
            if encrypt:
                writeInConsole(nameRoom + '/' + str(clientID), '***encrypt message***')
            else:
                writeInConsole(nameRoom + '/' + str(clientID), message)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def refreshClients(nameRoom, clientID=None):
    try:
        if clientID in dictRooms[nameRoom]['users'] or clientID is None:
            admin = dictRooms[nameRoom]['admin']
            if nameRoom in dictRooms.keys():
                for usr in dictRooms[nameRoom]['users']:
                    if clientID != usr:
                        setRSAKeyClient(usr, clientID, nameRoom)
                for req in dictRooms[nameRoom]['requests']:
                    setRSAKeyClient(req, clientID, nameRoom)
                sendData = {'command': '-sRefreshUsers',
                            'admin': admin,
                            'users': dictRooms[nameRoom]['users'],
                            'requests': dictRooms[nameRoom]['requests'],
                            'room': nameRoom}
                if clientID is None:
                    broadcastMessage(sendData, clientID, nameRoom)
                else:
                    sendOneClientMessage(sendData, clientID)
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def setRSAKeyClient(user, clientID, nameRoom=None):
    try:
        keyRSA = dictClients[user]['Public_Key']
        sendData = {'command': '-sSetRSAKeyClient', 'user': user, 'keyRSA': keyRSA}
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
                    writeInConsole(str(clientID), 'Confirmed! Entered the room ' + nameRoom)
                else:
                    writeInConsole(str(clientID), 'Sent a request to enter the room ' + nameRoom)
                    dictRooms[nameRoom]['requests'].append(clientID)
                refreshClients(nameRoom)
        else:
            writeInLogClient('error. Room does not exist', clientID, 'red', nameRoom)
            writeInConsole('error', 'Room ' + nameRoom + ' does not exist')
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
                    setRoomRight(approvedID, nameRoom, 2, 'green', welcome, data['CryptPrivatKeyRoom'])
                    refreshClients(nameRoom)
                    writeInConsole(str(approvedID), 'Confirmed! Entered the room ' + nameRoom)
                else:
                    writeInConsole('error', 'user ' + str(approvedID) + ' not in server')
            else:
                writeInConsole('error', 'Admin tell "NO"!')
        else:
            writeInConsole('error', str(clientID) + ' not Admin!')
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def exitRoom(nameRoom, clientID):
    try:
        if clientID in dictRooms[nameRoom]['users']:
            removeUserFromRoom(nameRoom, clientID)
            welcome = 'You left the room'
            setRoomRight(clientID, nameRoom, 0, 'purple', welcome)
        elif clientID in dictRooms[nameRoom]['requests']:
            dictRooms[nameRoom]['requests'].remove(clientID)
            welcome = 'You canceled request'
            setRoomRight(clientID, nameRoom, 0, 'purple', welcome)
            refreshClients(nameRoom)
        writeInConsole(str(clientID), '-sExit room ' + nameRoom)
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
            writeInConsole(str(clientID), 'create new room: ' + nameRoom)
        else:
            writeInLogClient(validName['msg'], clientID, 'purple', nameRoom)
            writeInConsole(str(clientID), '-sNewRoom error: ' + validName['msg'])
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
            writeInConsole(str(clientID), '-sKickUser. kick user:' + str(kickId))
    except Exception as error:
        excaptionWrite(error, clientID, nameRoom)
    return None


def sendKeyAES(data, clientID):
    nameRoom = None
    try:
        nameRoom = data['room']
        clientSend = int(data['id'])
        if clientID == dictRooms[nameRoom]['admin'] and clientSend != clientID:
            sendData = {'command': '-sSetKeyAES',
                        'room': nameRoom,
                        'encryptKeysAES': data['encryptKeysAES']}
            sendOneClientMessage(sendData, clientSend)
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
    prefix = 'Try'
    text = 'name Function: ' + str(nameFun) + ', c[' + str(ClientID) +\
           '], r[' + str(nameRoom) + ']: ' + str(errorTry)
    writeInConsole(prefix, text)
    return None


def writeInConsole(prefix, text):
    print(prefix + ': ' + text)


if __name__ == '__main__':
    randomGenerator = Random.new().read
    privateKey = RSA.generate(2048, randomGenerator)
    publicKey = privateKey.publickey()
    globalPublic = publicKey.exportKey().decode('utf-8')
    globalPrivate = bytes(privateKey.exportKey())

    #   dictRooms['BigSizeRoom'] = {'admin': None, 'users': [], 'requests': []}
    #   for usrFake in range(80):
    #       MainBegin('fake')

    while True:
        connSocket, addr = server.accept()
        MainBegin(connSocket)
