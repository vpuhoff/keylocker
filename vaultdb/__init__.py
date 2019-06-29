import pickledb
import fire
from cryptography.fernet import Fernet

class Storage(object):
    def __init__(self, filename='secrets.json', key_file='storage.key'):
        self.db = pickledb.load(filename,True)
        with open(key_file,'rb') as keyfile:
            key = keyfile.read()
        self.fernet = Fernet(key)
   
    def __setitem__(self, key, value):
        self.db[key] = self.fernet.encrypt(value.encode()).decode()
 
    def __getitem__(self, key):
        return self.fernet.decrypt(self.db[key].encode()).decode()

    def keys(self):
        return self.db.getall()
