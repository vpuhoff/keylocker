from . import Storage

import fire 
class Manager(object):
    def __init__(self):
        self.storage = Storage()
        return super().__init__()

    def init(self):
        import base64
        import os
        from cryptography.fernet import Fernet
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        key = Fernet.generate_key()
        longpass = key
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(longpass))
        with open('storage.key','wb') as f:
            f.write(key)
        return 'storage.key'
        # key = Fernet.generate_key()
        # return (key.decode())
    def write(self,key, value):
        self.storage[key]=value
        return 'OK'
        

    def remove(self,key):
        if key =='*':
            for key,value in self.storage.db.dgetall():
                self.storage.db.drem(key)
        else:
            try:
                self.storage.db.drem(key)
                return 'OK'
            except KeyError as e:
                print('ERROR: Key not found')
                exit(888)
        
    def read(self,key):
        return self.storage[key]

    def list(self):
        for item in list(self.storage.keys()):
            print(item)


def main():
    fire.Fire(Manager, name='keylocker')    