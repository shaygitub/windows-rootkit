curl http://192.168.1.21:8080/package.zip --output suspack.zip
tar -xf suspack.zip
del /f suspack.zip
cd package\FunEngine\x64\Debug
FunEngine.exe