del *.sdf
del /a:h *.suo
rmdir /s /q ipch
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q DrvLoader\Debug
rmdir /s /q DrvLoader\Release
del /s *.aps
pause
