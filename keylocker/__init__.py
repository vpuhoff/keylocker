import pickledb
import fire
from cryptography.fernet import Fernet, InvalidToken

class Storage(object):
    def __init__(self, filename='secrets.json', key_file='storage.key', key=None):
        self.db = pickledb.load(filename,True)
        try:
            if not key:
                with open(key_file,'rb') as keyfile:
                    key = keyfile.read()
            self.fernet = Fernet(key)
        except FileNotFoundError as e:
            print('ERROR: Key file not found!')
        
    def __setitem__(self, key, value):
        self.db[key] = self.fernet.encrypt(str(value).encode()).decode()
 
    def __getitem__(self, key):
        try:
            raw= self.db[key]
            if raw:
                raw = str(raw)
                return self.fernet.decrypt(raw.encode()).decode()
            else:
                print('ERROR: Key not found')
                exit(999)
        except InvalidToken as e:
            print('ERROR: Invalid key file!')
            exit(999)
        except FileNotFoundError as e:
            print('ERROR: Key file not found!')
            exit(999)
        
    def keys(self):
        return self.db.getall()
