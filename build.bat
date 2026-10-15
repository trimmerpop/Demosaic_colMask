@echo off
setlocal
REM Emit Python/pip output as UTF-8 so redirected logs stay readable in editors.
set "PYTHONIOENCODING=utf-8"
cd /d "%~dp0"

REM ===========================================================================
REM  Demosaic Tool (colMask) - Windows build script
REM
REM  Steps
REM    1) Update UnityPy to the latest release  (pip install --upgrade unitypy)
REM    2) Install runtime / build dependencies  (requirements*.txt)
REM    3) (optional) Regenerate the icon        (make_icon.py)
REM    4) Build with PyInstaller                (demosaic colMask.spec)
REM    5) Verify the UnityPy version bundled into the new executable
REM
REM  Usage
REM    build.bat             update UnityPy, then build
REM    build.bat /noupdate   build with the currently installed UnityPy
REM    build.bat /icon       regenerate the icon (.ico / .png) before building
REM    build.bat /noverify   skip the bundled-version verification
REM
REM  NOTE: keep this file ASCII-only. cmd.exe mis-parses non-ASCII batch files.
REM ===========================================================================

set "UPDATE_UNITYPY=1"
set "MAKE_ICON=0"
set "VERIFY=1"

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="/noupdate" set "UPDATE_UNITYPY=0"
if /i "%~1"=="/icon"     set "MAKE_ICON=1"
if /i "%~1"=="/noverify" set "VERIFY=0"
shift
goto :parse_args
:args_done

echo =================================================================
echo  Demosaic Tool (colMask) build
echo  work dir : %CD%
echo =================================================================
echo.

echo [1/5] Checking Python
python --version
if errorlevel 1 (
    echo [X] python was not found. Check your PATH.
    goto :failed
)

echo.
if "%UPDATE_UNITYPY%"=="1" (
    echo [2/5] Updating UnityPy to the latest release
    python -c "import UnityPy;print('    before : UnityPy', UnityPy.__version__)" 2>nul || echo     before : UnityPy ^(not installed^)
    python -m pip install --upgrade unitypy
    if errorlevel 1 (
        echo [X] Failed to update UnityPy.
        goto :failed
    )
    python -c "import UnityPy;print('    after  : UnityPy', UnityPy.__version__)"
) else (
    echo [2/5] Skipping the UnityPy update ^(/noupdate^)
    python -c "import UnityPy;print('    current: UnityPy', UnityPy.__version__)"
)
if errorlevel 1 (
    echo [X] Failed to import UnityPy.
    goto :failed
)

echo.
echo [3/5] Checking runtime / build dependencies
python -m pip install -r requirements.txt
if errorlevel 1 goto :failed
python -m pip install -r requirements-build.txt
if errorlevel 1 goto :failed

echo.
if "%MAKE_ICON%"=="1" (
    echo [4/5] Regenerating the icon ^(make_icon.py^)
    python make_icon.py
    if errorlevel 1 goto :failed
) else (
    echo [4/5] Skipping icon regeneration ^(use: build.bat /icon^)
)

echo.
echo [5/5] Building with PyInstaller
echo       Tip: build.bat ^> build\build.log 2^>^&1  ^(saves the whole log to a file^)
python -m PyInstaller --noconfirm --clean "demosaic colMask.spec"
if errorlevel 1 goto :failed

echo.
if "%VERIFY%"=="1" (
    echo [verify] Checking the UnityPy version bundled in the built exe
    python verify_bundled_unitypy.py
    if errorlevel 1 (
        echo [X] The bundled UnityPy version does not match the expected version.
        goto :failed
    )
) else (
    echo [verify] Skipped ^(/noverify^)
)

echo.
echo [OK] Build finished. Check the dist folder.
for %%F in ("dist\demosaic colMask v*.exe") do echo      %%~F
exit /b 0

:failed
echo.
echo [X] Build aborted. Check the messages above.
exit /b 1
