from PyQt5.QtCore import pyqtSignal, QThread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import json


class WorkThread(QThread):
    replyServer = pyqtSignal(dict)

    def __init__(self, server, key):
        super().__init__()
        self.server = server
        self.key = key
        privateKey = RSA.importKey(key)
        self.myCipherRSA = PKCS1_OAEP.new(privateKey)

    @property
    def run(self):
        stackPackets = b''
        while True:
            packNow = None
            try:
                dataJson = self.server.recv(4096)
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
                                        self.replyServer.emit(data)
                            stackPackets = b''
                    else:
                        stackPackets = b''
                        print('bad packet: ' + str(packNow))
                else:
                    errorMsg = 'Error Disconnect server'
                    self.disconnectEvent(errorMsg)
                    break
            except json.decoder.JSONDecodeError as errorTry:
                self.excaptionWrite(errorTry)
                print('bad packet: ' + str(packNow))
            except Exception as errorTry:
                self.excaptionWrite(errorTry)
                break
        print('exit cycle "while" / disconnect server')
        return None

    def decodePacket(self, encPack):
        try:
            encSessionKey = bytes.fromhex(encPack[0])
            nonce = bytes.fromhex(encPack[1])
            cipherText = bytes.fromhex(encPack[2])
            tag = bytes.fromhex(encPack[3])

            sessionKey = self.myCipherRSA.decrypt(encSessionKey)
            cipherAES = AES.new(sessionKey, AES.MODE_EAX, nonce)
            dataDump = cipherAES.decrypt_and_verify(cipherText, tag)
            data = json.loads(dataDump.decode('utf-8'))
            return data
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return None

    def disconnectEvent(self, message):
        errorSend = {'command': '-sError', 'type': 'exit',
                     'text': message, 'room': None, 'address': None}
        self.replyServer.emit(errorSend)

    def excaptionWrite(self, errorTry):
        import inspect
        nameFun = inspect.stack()[1][3]
        errorMsg = 'nameFun: ' + str(nameFun) + '. TRY: ' + str(errorTry)
        errorSend = {'command': '-sError', 'type': 'orange',
                     'text': errorMsg, 'room': None, 'address': None}
        self.replyServer.emit(errorSend)
        return None
