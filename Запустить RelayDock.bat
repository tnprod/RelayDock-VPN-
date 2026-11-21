@echo off
chcp 65001 >nul
setlocal
title RelayDock
if not exist "%~dp0RelayDock.exe" goto incomplete
if not exist "%~dp0_internal\" goto incomplete
cd /d "%~dp0"
echo Открываем RelayDock в браузере...
echo Оставьте это окно открытым, пока пользуетесь интерфейсом.
echo После закрытия программы настроенный VPN продолжит работать на VPS.
echo.
"%~dp0RelayDock.exe"
set "RELAYDOCK_EXIT_CODE=%ERRORLEVEL%"
if not "%RELAYDOCK_EXIT_CODE%"=="0" (
    echo.
    echo Не удалось запустить RelayDock. Текст ошибки показан выше.
    pause
)
exit /b %RELAYDOCK_EXIT_CODE%

:incomplete
echo Сначала распакуйте Windows-архив целиком: нажмите на ZIP правой кнопкой
echo мыши и выберите «Извлечь все». Затем откройте распакованную папку.
echo.
echo Рядом с этим файлом должны находиться RelayDock.exe и папка _internal.
echo Готовая сборка: https://github.com/tnprod/RelayDock-VPN-/releases
echo.
pause
exit /b 1
