@echo off
cd /d "%~dp0"
if exist "%LOCALAPPDATA%\hermes\tools\node-26.7.0-win32-x64\node.exe" set "PATH=%LOCALAPPDATA%\hermes\tools\node-26.7.0-win32-x64;%PATH%"
set SYNAPSE_TELEMETRY=0
echo Starting COMET x Synapse Hackathon Studio at http://127.0.0.1:8100 ...
".venv\Scripts\python.exe" start_studio.py
