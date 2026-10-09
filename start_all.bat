@echo off
title CTIMS — Starting All Services
echo ================================================
echo   CTIMS — Cyber Threat Intelligence Dashboard
echo ================================================
echo.

echo [1/2] Starting FastAPI backend on port 8000...
start "CTIMS FastAPI" cmd /k "cd /d "%~dp0backend" && "C:\Users\varsh\AppData\Local\Programs\Python\Python312\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Next.js dashboard on port 3000...
start "CTIMS Dashboard" cmd /k "cd /d "%~dp0dashboard" && npm run dev"

echo.
echo ================================================
echo   Dashboard:  http://localhost:3000
echo   FastAPI:    http://localhost:8000
echo   API Docs:   http://localhost:8000/docs
echo   Test PCAPs: test_files\
echo ================================================
echo.
pause
