@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "C:\Users\пк\Desktop\universal-re-agent\data\training"
cl.exe /O1 /nologo base64_decode.c /Fe:base64_decode.exe
echo EXIT:%ERRORLEVEL%
