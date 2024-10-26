@echo off
REM Check if Python 3 is installed
python --version 2>NUL | findstr /R "^Python 3" >NUL
IF %ERRORLEVEL% NEQ 0 (
    echo Python 3 is not installed. Please install Python 3 first.
    exit /b 1
) ELSE (
    echo Python 3 is installed.
)


REM Upgrade pip to the latest version
echo Installing or upgrading pip...
python -m pip install --upgrade pip

REM Create virtual environment
echo Creating virtual environment named "venv_batch_attendance"
python -m venv venv_batch_attendance

REM Activate virtual environment
echo Activating virtual environment...
venv_batch_attendance\Scripts\activate

