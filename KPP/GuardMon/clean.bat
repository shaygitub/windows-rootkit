@echo off
del *.sdf
del *.VC.db
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q GuardMon\x64
rmdir /s /q GuardMon\Debug
rmdir /s /q GuardMon\Release
cd HyperPlatform
clean.bat
