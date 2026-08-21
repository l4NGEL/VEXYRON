# PyInstaller spec for the VEXYRON webapp -- tek dosyalik, cift-tiklanan .exe.
# Derlemek icin: pyinstaller vexyron.spec
#
# vulnerable-app kasitli olarak bu pakete dahil DEGIL -- o ogretici bir kaynak
# koddur, ayri "python run.py" ile calistirilmasi beklenir.

import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.dirname(os.path.abspath(SPEC)))
WEBAPP_DIR = os.path.join(ROOT, "webapp")
SCANNER_DIR = os.path.join(ROOT, "scanner")

hiddenimports = (
    collect_submodules("core")
    + collect_submodules("checks")
    + collect_submodules("mobile")
    + collect_submodules("network")
    + collect_submodules("loadtest")
    + collect_submodules("report")
    + collect_submodules("smoketest")
    + ["safety", "vulndb"]
)

datas = [
    (os.path.join(WEBAPP_DIR, "templates"), "webapp/templates"),
    (os.path.join(WEBAPP_DIR, "static"), "webapp/static"),
]
datas += collect_data_files("reportlab")

a = Analysis(
    [os.path.join(WEBAPP_DIR, "app.py")],
    pathex=[WEBAPP_DIR, SCANNER_DIR],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="VEXYRON",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
