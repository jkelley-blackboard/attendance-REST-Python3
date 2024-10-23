@echo off
REM Check if Python is installed
python --version
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed. Please install Python first.
    exit /b 1
)

REM Upgrade pip to the latest version
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install required Python packages
echo Installing required Python packages...

pip install datetime
pip install argparse
pip install configparser
pip install logging
pip install requests
pip install typing

REM Verify installations
echo Verifying installations...
pip list

echo Setup complete!
pause