@echo off
cd /d "%~dp0"
python lan_inspector.py --scanner
if errorlevel 1 pause
