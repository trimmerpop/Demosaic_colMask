# -*- mode: python ; coding: utf-8 -*-
import os
import re

from PyInstaller.utils.hooks import collect_data_files

# 스크립트의 APP_VERSION 을 읽어 실행 파일 이름에 사용한다 (예: 'demosaic colMask v1.05.exe')
script_path = os.path.join(SPECPATH, 'demosaic colMask.py')
with open(script_path, encoding='utf-8') as fp:
    matched = re.search(r'^APP_VERSION\s*=\s*(.+)$', fp.read(), re.M)
app_version = matched.group(1).strip().strip('\'"') if matched else '0.00'
exe_name = f'demosaic colMask v{app_version}'

# 아이콘 파일 경로 (spec 파일이 있는 디렉터리 기준)
icon_path = os.path.join(SPECPATH, 'demosaic colMask.ico')

datas = []
datas += collect_data_files('UnityPy')
# 창 아이콘용 .ico (실행 시 sys._MEIPASS 에서 읽는다)
datas += [(icon_path, '.')]


a = Analysis(
    ['demosaic colMask.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=exe_name,
    icon=icon_path,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
