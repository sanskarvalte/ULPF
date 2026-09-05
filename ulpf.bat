@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "PYTHONPATH=%SCRIPT_DIR%backend"
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    "%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%backend\app\main.py" %*
) else (
    python "%SCRIPT_DIR%backend\app\main.py" %*
)
exit /b %ERRORLEVEL%
