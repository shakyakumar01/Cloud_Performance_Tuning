import os
import time
import base64
from Crypto.Cipher import AES

from secretsharing import PlaintextToHexSecretSharer
from secretsharing import SecretSharer

BS = 16
pad = lambda s: s + bytes([BS - len(s) % BS] * (BS - len(s) % BS))
unpad = lambda s: s[:-s[-1]]

def shamirs_split(file_object):
    text = file_object.read()
    secret_shares = PlaintextToHexSecretSharer.split_secret(text, 2, 2)
    hexcodes = [SecretSharer.split_secret(share[2:], 2, 2) for share in secret_shares]
    return hexcodes, secret_shares[0]

def shamirs_join(hexcodes, text):
    msg_alpha = SecretSharer.recover_secret(hexcodes[0:2])
    msg_alpha = '1-' + msg_alpha
    secret_shares = [msg_alpha, text]
    text = PlaintextToHexSecretSharer.recover_secret(secret_shares)
    return text

def iv():
    return os.urandom(16)

class AESCipher(object):
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        raw = pad(message.encode('utf-8'))
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CBC, iv())
        enc = cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CBC, iv())
        dec = cipher.decrypt(enc)
        return unpad(dec).decode('utf-8', errors='replace')

