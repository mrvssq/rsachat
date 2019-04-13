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
                        commandRight = self.commandHandler(command)
                        if commandRight is not None:
                            self.replyServer.emit(commandRight)
                else:
                    error = 'Error Disconnect server'
                    self.replyServer.emit({'command': '-sError', 'type': 'exit', 'error': error})
                    break
            except Exception as errorTry:
                errorMsg = 'cycle "while" run. try: ' + str(errorTry)
                errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
                self.replyServer.emit(errorSend)
                break
        print('exit cycle "while" / disconnect server')
        return None

    def commandHandler(self, command):
        try:
            if command:
                commandWithJson = b''
                blocks = command[11:-11].split(b'--[SPLIT]--')
                for block in blocks:
                    commandWithJson += self.key.decrypt(block)
                commandRight = json.loads(commandWithJson.decode('utf-8'))
                print(commandRight)
                return commandRight
        except Exception as errorTry:
            errorMsg = 'commandHandler. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.replyServer.emit(errorSend)
            return None
