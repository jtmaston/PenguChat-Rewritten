# -*- mode: python ; coding: utf-8 -*-

from kivy_deps import sdl2, glew
block_cipher = None


a = Analysis(['Server\\server.py'],
             pathex=['C:\\Users\\aanas\\PycharmProjects\\PenguChat-redesigned'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,Tree('C:\\Users\\aanas\\PycharmProjects\\PenguChat-redesigned\\Server\\'),
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          *[Tree(p) for p in (sdl2.dep_bins + glew.dep_bins)],
          name='PenguChat Server',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
