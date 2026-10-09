@echo off
echo ============================================================
echo  CTIMS - Compile and Run
echo ============================================================

set SRC=src
set BIN=bin
set LIB=lib
set JAR=lib\postgresql-42.7.4.jar
set MAIN=CTIMS

echo.
echo [1/3] Checking JDBC driver...
if not exist %JAR% (
    echo  Downloading PostgreSQL JDBC driver...
    powershell -Command "Invoke-WebRequest -Uri 'https://jdbc.postgresql.org/download/postgresql-42.7.4.jar' -OutFile '%JAR%'"
    if errorlevel 1 (
        echo  [ERROR] Download failed. Check internet connection.
        pause
        exit /b 1
    )
    echo  [OK] JDBC driver downloaded.
) else (
    echo  [OK] JDBC driver found.
)

echo.
echo [2/3] Compiling Java source files...
if not exist %BIN% mkdir %BIN%
javac -encoding UTF-8 -cp %JAR% -d %BIN% %SRC%\*.java
if errorlevel 1 (
    echo  [ERROR] Compilation failed. Check errors above.
    pause
    exit /b 1
)
echo  [OK] Compilation successful.

echo.
echo [3/3] Running CTIMS...
echo ============================================================
java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -cp "%BIN%;%JAR%" %MAIN%

pause
