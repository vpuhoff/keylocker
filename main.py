import pickledb
import fire
from cryptography.fernet import Fernet
 
class Storage(object):
    def __init__(self, filename='storage.db', key_file='storage.key'):
        self.db = pickledb.load(filename,True)
        with open(key_file,'rb') as keyfile:
            key = keyfile.read()
        self.fernet = Fernet(key)
   
    def __setitem__(self, key, value):
        self.db[key] = self.fernet.encrypt(value.encode()).decode()
 
    def __getitem__(self, key):
        return self.fernet.decrypt(self.db[key]) 

    def keys(self):
        return self.db.getall()
 
def GenerateKey():
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

# class Manager(object):
#     def generate_key(self):
#         return GenerateKey()
#         # key = Fernet.generate_key()
#         # return (key.decode())
#     def add_item(self,file='storage.db', key_file = 'storage.key', table ='default'):
#         storage = Storage(file,key_file,table)
#         print('Enter key name:')
#         key = input()
#         print('Enter value:')
#         value1 = input()
#         print('Retry value:')
#         value2 = input()
#         if value1==value2:
#             storage[key]=value1
#         return 'OK'
#     def list_items(self):
#         st

# if __name__ == '__main__':
#     fire.Fire(Manager)

# exit()  
# f = Fernet(key)
# token = f.encrypt(b"A really secret message. Not for prying eyes.")
# f.decrypt(token)
if __name__ == '__main__':
    from asciimatics.widgets import Frame, TextBox, Layout, Label, Divider, Text, \
        CheckBox, RadioButtons, Button, PopUpDialog, TimePicker, DatePicker, Background, DropdownList, \
        PopupMenu
    from asciimatics.event import MouseEvent
    from asciimatics.scene import Scene
    from asciimatics.screen import Screen
    from asciimatics.exceptions import ResizeScreenError, NextScene, StopApplication, InvalidFields
    import sys
    import re
    import datetime
    import logging

    db = Storage()
    # Initial data for the form
    logging.basicConfig(filename="forms.log", level=logging.INFO)
    logging.info(db.keys())

    from add_item import AddItemFrame
    from menu_builder import MenuBuilderFrame
    from item_menu import ItemFrame

    def AddItem(screen, scene):
        screen.play([Scene([
            Background(screen),
            AddItemFrame(screen,db)
        ], -1)], stop_on_resize=True, start_scene=scene, allow_int=True)

    def ShowAddItem():
        Screen.wrapper(AddItem, catch_interrupt=False, arguments=[last_scene])

    def Item(screen, scene, key):
        screen.play([Scene([
            Background(screen),
            ItemFrame(screen,db,{
                'key':key
            })
        ], -1)], stop_on_resize=True, start_scene=scene, allow_int=True)

    def ListItems(screen, scene):
        items = {}
        for key in db.keys():
            items[key]=lambda key: Screen.wrapper(Item, catch_interrupt=False, arguments=[last_scene,key])
        screen.play([Scene([
            Background(screen),
            MenuBuilderFrame(screen,data={
                "label":"*** Объекты в хранилище  ***",
                "items":items
            })
        ], -1)], stop_on_resize=True, start_scene=scene, allow_int=True)

    def ShowListItem():
        Screen.wrapper(ListItems, catch_interrupt=False, arguments=[last_scene])


    def MainMenu(screen, scene):
        screen.play([Scene([
            Background(screen),
            MenuBuilderFrame(screen,data={
                "label":"*** Добро пожаловать в редактор хранилища. Выберите операцию.  ***",
                "items":{
                    "Список объектов":ShowListItem,
                    "Добавить объект":ShowAddItem,
                    "Сгенерировать ключ":GenerateKey
                }
            })
        ], -1)], stop_on_resize=True, start_scene=scene, allow_int=True)


    last_scene = None
    while True:
        try:
            # Screen.wrapper(AddItem, catch_interrupt=False, arguments=[last_scene])
            Screen.wrapper(MainMenu, catch_interrupt=False, arguments=[last_scene])
            sys.exit(0)
        except ResizeScreenError as e:
            last_scene = e.scene