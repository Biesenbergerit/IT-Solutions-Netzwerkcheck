@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
title IT-Solutions Netzwerkcheck Build

echo.
echo ==========================================
echo IT-Solutions Netzwerkcheck EXE Builder
echo ==========================================
echo.
echo Hinweis:
echo Diese Datei ist nur fuer dich als Entwickler.
echo Der Kunde bekommt spaeter nur die fertige EXE.
echo.

set PYTHON_CMD=

echo Suche echte Python Installation...
echo.

REM 1. Bevorzugt den Python Launcher verwenden, weil "python.exe" oft vom Microsoft Store Alias blockiert wird.
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 --version >nul 2>nul
    if %errorlevel%==0 (
        set PYTHON_CMD=py -3
        goto python_found
    )
)

REM 2. Danach python pruefen, aber nur wenn es wirklich funktioniert.
where python >nul 2>nul
if %errorlevel%==0 (
    python --version >nul 2>nul
    if %errorlevel%==0 (
        set PYTHON_CMD=python
        goto python_found
    )
)

REM 3. Bekannte Standardpfade pruefen.
for %%P in (
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
) do (
    if exist %%P (
        %%P --version >nul 2>nul
        if !errorlevel!==0 (
            set PYTHON_CMD=%%P
            goto python_found
        )
    )
)

echo FEHLER: Keine funktionierende Python Installation gefunden.
echo.
echo Sehr wahrscheinlich ist der Microsoft Store Alias aktiv oder Python ist nicht im PATH.
echo.
echo Loesung 1:
echo Einstellungen ^> Apps ^> Erweiterte App-Einstellungen ^> App-Ausfuehrungsaliase
echo Dort deaktivieren:
echo python.exe
echo python3.exe
echo.
echo Loesung 2:
echo Python von python.org neu installieren und "Add python.exe to PATH" aktivieren.
echo.
echo Teste danach in einem neuen CMD-Fenster:
echo py -3 --version
echo python --version
echo.
pause
exit /b 1

:python_found
echo Python gefunden:
%PYTHON_CMD% --version
echo.

echo Pruefe pip...
%PYTHON_CMD% -m pip --version >nul 2>nul
if not %errorlevel%==0 (
    echo pip fehlt oder funktioniert nicht. Versuche ensurepip...
    %PYTHON_CMD% -m ensurepip --upgrade
    if not %errorlevel%==0 (
        echo FEHLER: pip konnte nicht eingerichtet werden.
        pause
        exit /b 1
    )
)

echo.
echo Aktualisiere pip...
%PYTHON_CMD% -m pip install --upgrade pip
if not %errorlevel%==0 (
    echo FEHLER: pip konnte nicht aktualisiert werden.
    pause
    exit /b 1
)

echo.
echo Installiere PyInstaller...
%PYTHON_CMD% -m pip install pyinstaller
if not %errorlevel%==0 (
    echo FEHLER: PyInstaller konnte nicht installiert werden.
    pause
    exit /b 1
)

echo.
echo Erstelle Windows EXE...
%PYTHON_CMD% -m PyInstaller --onefile --windowed --clean --name IT-Solutions-Netzwerkcheck netzwerkcheck.py
if not %errorlevel%==0 (
    echo FEHLER: Build fehlgeschlagen.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Fertig.
echo ==========================================
echo.
echo Die fertige Kunden-Datei liegt hier:
echo dist\IT-Solutions-Netzwerkcheck.exe
echo.
echo Diese EXE kannst du auf deine Website stellen.
echo Der Kunde braucht KEIN Python.
echo.
pause
