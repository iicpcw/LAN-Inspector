@echo off
cd /d "%~dp0"
python lan_inspector.py --local-ports
if errorlevel 1 pause
