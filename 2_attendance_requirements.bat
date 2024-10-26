@echo off

REM Upgrade pip to the latest version
echo Installing or upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo Updating/installing required modules from attendance_requirements.txt
pip install -r attendance_requirements.txt
