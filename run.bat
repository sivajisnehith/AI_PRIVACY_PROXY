@echo off
title AI Privacy Proxy
cls
echo Starting AI Privacy Proxy...
"%~dp0.venv\Scripts\python.exe" "%~dp0main.py" %*
if errorlevel 1 pause
