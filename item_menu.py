from asciimatics.widgets import Frame, TextBox, Layout, Label, Divider, Text, \
    CheckBox, RadioButtons, Button, PopUpDialog, TimePicker, DatePicker, Background, DropdownList, \
    PopupMenu
from asciimatics.event import MouseEvent
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import ResizeScreenError, NextScene, StopApplication, InvalidFields



class ItemFrame(Frame):
    def __init__(self, screen, db, form_data):
        super(ItemFrame, self).__init__(screen,
                                        int(screen.height * 2 // 3),
                                        int(screen.width * 2 // 3),
                                        data=form_data,
                                        has_shadow=True,
                                        name="Add new key")
        self.set_theme("bright")
        self.db = db
        layout = Layout([1, 18, 1])
        self.add_layout(layout)
        layout.add_widget(Divider(height=1), 1)
        layout.add_widget(Label("Объект:"+form_data['key']), 1)
        layout.add_widget(Divider(height=1), 1)
        layout.add_widget(Button("Редактировать", self._edit), 1)
        layout.add_widget(Button("Удалить", self._delete), 1)
        layout.add_widget(Button("Выход", self._quit), 2)
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

    def _edit(self):
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

    def _delete(self):
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
