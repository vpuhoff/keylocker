from asciimatics.widgets import Frame, TextBox, Layout, Label, Divider, Text, \
    CheckBox, RadioButtons, Button, PopUpDialog, TimePicker, DatePicker, Background, DropdownList, \
    PopupMenu
from asciimatics.event import MouseEvent
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import ResizeScreenError, NextScene, StopApplication, InvalidFields

form_data = {
    "key": "", 
    "value" : ""
}

class AddItemFrame(Frame):
    def __init__(self, screen, db):
        super(AddItemFrame, self).__init__(screen,
                                        int(screen.height * 2 // 3),
                                        int(screen.width * 2 // 3),
                                        data=form_data,
                                        has_shadow=True,
                                        name="Add new key")
        self.set_theme("bright")
        self.db = db
        layout = Layout([1, 18, 1])
        self.add_layout(layout)
        self._reset_button = Button("Сбросить", self._reset)
        layout.add_widget(
            Text(label="Имя объекта:",
                 name="key",
                 on_change=self._on_change,
                 validator="^[a-zA-Z_/-/.]*$"), 1)
        layout.add_widget(Text("Значение:", name="value", on_change=self._on_change), 1)
        layout.add_widget(Divider(height=3), 1)
        layout2 = Layout([1, 1, 1])
        self.add_layout(layout2)
        layout2.add_widget(self._reset_button, 0)
        layout2.add_widget(Button("Добавить объект", self._view), 1)
        layout2.add_widget(Button("Выход", self._quit), 2)
        self.fix()

    def _on_change(self):
        changed = False
        self.save()
        for key, value in self.data.items():
            if key not in form_data or form_data[key] != value:
                changed = True
                break
        self._reset_button.disabled = not changed

    def _reset(self):
        self.reset()
        raise NextScene()

    def _view(self):
        # Build result of this form and display it.
        try:
            self.save(validate=True)
            self.db[self.data['key']]=self.data['value']
            self._scene.add_effect(
                PopUpDialog(self._screen, "Объект добавлен.", ["OK"]))
        except InvalidFields as exc:
            message = "Есть ошибки в данных полях:\n\n"
            for field in exc.fields:
                message += "- {}\n".format(field)
            self._scene.add_effect(
                PopUpDialog(self._screen, message, ["OK"]))
        

    def _quit(self):
        self._scene.add_effect(
            PopUpDialog(self._screen,
                        "Вы уверены?",
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
