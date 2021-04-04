set version=2.0

set x86=x86
set x64=x86_64

set new_ver=%version%\%x64%
set legacy_ver=%version%\%x86%

Devkit\python.exe -m PyInstaller --onefile --distpath ..\Releases\%new_ver%\ --noconfirm  ../PenguChat.spec
Devkit_legacy\python.exe -m PyInstaller --onefile --distpath ..\Releases\%legacy_ver%\ --noconfirm ../PenguChat.spec

Devkit\python.exe -m PyInstaller --onefile --distpath ..\Releases\%new_ver%\ --noconfirm ../server.spec
Devkit_legacy\python.exe -m PyInstaller --onefile --distpath ..\Releases\%legacy_ver%\ --noconfirm ../server.spec