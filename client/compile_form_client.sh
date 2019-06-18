#!/bin/bash
pyuic5 Forms/main.ui > main_ui.py

pyuic5 Forms/WidgetTemplateChat.ui > WidgetTemplateChat_ui.py
pyuic5 Forms/WidgetLog.ui > WidgetLog_ui.py
pyuic5 Forms/WidgetMyKeys.ui > WidgetMyKeys_ui.py
pyuic5 Forms/WidgetGenRandom.ui > WidgetGenRandom_ui.py

pyuic5 Forms/DialogAbout.ui > DialogAbout_ui.py
pyuic5 Forms/DialogSettingsRoom.ui > DialogSettingsRoom_ui.py
