@echo off
REM Build a pure-Python Lambda deployment zip.
REM Produces deploy\lambda.zip containing the handler, the aisentinel package,
REM and only the pure-Python runtime deps (requests, pyyaml). boto3 is provided
REM by the Lambda runtime, so it is intentionally NOT bundled.

setlocal
set BUILD=deploy\build
set ZIP=deploy\lambda.zip

echo Cleaning previous build...
if exist "%BUILD%" rmdir /s /q "%BUILD%"
if exist "%ZIP%" del /q "%ZIP%"
mkdir "%BUILD%"

echo Installing runtime dependencies (pure-Python)...
pip install --target "%BUILD%" requests pyyaml --quiet

echo Copying application code...
xcopy /e /i /q aisentinel "%BUILD%\aisentinel" >nul
copy /y deploy\handler.py "%BUILD%\handler.py" >nul

echo Creating zip...
powershell -Command "Compress-Archive -Path '%BUILD%\*' -DestinationPath '%ZIP%' -Force"

echo.
echo Done. Package: %ZIP%
endlocal