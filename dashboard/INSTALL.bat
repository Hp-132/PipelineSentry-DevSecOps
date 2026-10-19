@echo off
echo Installing PipelineSentry Dashboard...
echo.
echo Step 1: Installing npm dependencies
npm install
if %errorlevel% neq 0 (
    echo Error: npm install failed
    pause
    exit /b 1
)
echo.
echo Step 2: Starting development server
echo Dashboard will open at http://localhost:5173
echo Press Ctrl+C to stop the server
echo.
npm run dev
