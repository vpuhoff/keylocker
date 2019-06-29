from asciimatics.widgets import Frame, TextBox, Layout, Label, Divider, Text, \
    CheckBox, RadioButtons, Button, PopUpDialog, TimePicker, DatePicker, Background, DropdownList, \
    PopupMenu
from asciimatics.event import MouseEvent,KeyboardEvent
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import ResizeScreenError, NextScene, StopApplication, InvalidFields


class MenuBuilderFrame(Frame):
    def __init__(self, screen, data):
        super(MenuBuilderFrame, self).__init__(screen,
                                        int(screen.height * 2 // 3),
                                        int(screen.width * 2 // 3),
                                        data=data,
                                        has_shadow=True,
                                        name="Main menu")
        self.set_theme("bright")
        layout = Layout([1, 18, 1])
        self.add_layout(layout)
        layout.add_widget(Label(data['label']), 1)
        self.targetaction = data['action']
        layout.add_widget(Divider(height=1), 1)
        for key in data['items']:
            layout.add_widget(Button(key,self.action ), 1)
        layout.add_widget(Divider(height=1), 1)
        layout.add_widget(Button("Выход", self._quit), 1)
        self.fix()

    def action(self):
        key = self.focussed_widget._text.replace('< ','').replace(' >','')
        self.targetaction(key,self.scene,self._screen)

    def _set_default(self):
        self.set_theme("default")

    def _quit(self):
        self._scene.add_effect(
            PopUpDialog(self._screen,
                        "Вы уверены, что хотите выйти?",
                        ["Да", "Нет"],
                        has_shadow=True,
                        on_close=self._quit_on_yes))

    @staticmethod
    def _check_email(value):
        m = re.match(r"^[a-zA-Z0-9_\-.]+@[a-zA-Z0-9_\-.]+\.[a-zA-Z0-9_\-.]+$",
                     value)
        return len(value) == 0 or m is not None

    @staticmethod
    def _quit_on_yes(selected):
        # Yes is the first button
        if selected == 0:
            raise StopApplication("User requested exit")
