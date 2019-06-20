from PyQt5.QtCore import pyqtSignal, QThread
from Crypto.PublicKey import RSA
import json


class WorkThread(QThread):
    replyServer = pyqtSignal(dict)

    def __init__(self, server, key):
        super().__init__()
        self.server = server
        keyBytes = bytes(key, "utf8")
        self.key = RSA.importKey(keyBytes)

    def run(self):
        while True:
            try:
                messageJson = self.server.recv(4096)
                if messageJson:
                    commands = messageJson[7:-5].split(b'}end}{begin{')
                    for command in commands:
                        commandRight = self.comandsHandlerServer(command)
                        if commandRight is not None:
                            self.replyServer.emit(commandRight)
                else:
                    errorMsg = 'Error Disconnect server'
                    self.disconnectEvent(errorMsg)
                    break
            except Exception as errorTry:
                self.excaptionWrite(errorTry)
                break
        print('exit cycle "while" / disconnect server')
        return None

    def comandsHandlerServer(self, command):
        try:
            if command:
                commandWithJson = b''
                blocks = command[11:-11].split(b'--[SPLIT]--')
                for block in blocks:
                    commandWithJson += self.key.decrypt(block)
                commandRight = json.loads(commandWithJson.decode('utf-8'))
                return commandRight
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
