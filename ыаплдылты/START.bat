@echo off
title DazzleMark Live Platform
setlocal
cd /d "%~dp0"

echo ============================================================
echo           DAZZLEMARK - НАСТОЯЩАЯ ФЭШН ПЛАТФОРМА
echo ============================================================
echo.

set "NODE_EXE=C:\Program Files\nodejs\node.exe"
if not exist "%NODE_EXE%" set "NODE_EXE=node"

:: Free port 8080 if taken
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":8080 "') do (
    taskkill /f /pid %%p >nul 2>&1
)

:: Ensure firewall port 8080 is open
netsh advfirewall firewall delete rule name="DazzleMark" >nul 2>&1
netsh advfirewall firewall add rule name="DazzleMark" dir=in action=allow protocol=TCP localport=8080 >nul 2>&1

:: Get Local IP
set "LOCAL_IP=192.168.0.194"
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr "IPv4"') do (
    set "LOCAL_IP=%%a"
    goto :IP_FOUND
)
:IP_FOUND
set "LOCAL_IP=%LOCAL_IP: =%"

echo [OK] Сервер запускается...
echo.
echo ------------------------------------------------------------
echo  На этом ПК приложение откроется прямо сейчас.
echo.
echo  Для входа с iPhone (должен быть в том же Wi-Fi):
echo  http://%LOCAL_IP%:8080
echo ------------------------------------------------------------
echo.
echo Окно не закрывайте, пока пользуетесь платформой!
echo.

:: Open browser on PC
start "" http://localhost:8080

:: Run Node server with full path
"%NODE_EXE%" server.js

pause
