#!/bin/bash
pyuic5 Forms/main.ui > ui_main.py

pyuic5 Forms/WidgetTemplateChat.ui > ui_widget_template_chat.py
pyuic5 Forms/WidgetLog.ui > ui_widget_log.py
pyuic5 Forms/WidgetMyKeys.ui > ui_widget_my_keys.py
pyuic5 Forms/WidgetGenRandom.ui > ui_widget_gen_random.py

pyuic5 Forms/DialogAbout.ui > ui_dialog_about.py
pyuic5 Forms/DialogSettingsRoom.ui > ui_dialog_settings_room.py
