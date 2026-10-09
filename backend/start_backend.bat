@echo off
title CTIMS FastAPI Backend
cd /d "%~dp0"
echo ============================================
echo   CTIMS FastAPI Backend  :  port 8000
echo ============================================
"C:\Users\varsh\AppData\Local\Programs\Python\Python312\python.exe" -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
