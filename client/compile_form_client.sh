#!/bin/bash
pyuic5 Forms/main.ui > ui_main.py

pyuic5 Forms/WidgetTemplateChat.ui > ui_WidgetTemplateChat.py
pyuic5 Forms/WidgetLog.ui > ui_WidgetLog.py
pyuic5 Forms/WidgetMyKeys.ui > ui_WidgetMyKeys.py
pyuic5 Forms/WidgetGenRandom.ui > ui_WidgetGenRandom.py

pyuic5 Forms/DialogAbout.ui > ui_DialogAbout.py
pyuic5 Forms/DialogSettingsRoom.ui > ui_DialogSettingsRoom.py
