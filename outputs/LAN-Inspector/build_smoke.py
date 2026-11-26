"""Opt-in non-network smoke test for a packaged application."""
import json
from pathlib import Path
import sys
import tempfile
import tkinter as tk
from unittest.mock import patch


def run_smoke():
    output=Path(sys.argv[sys.argv.index('--self-test-output')+1])
    result={}
    try:
        from app_paths import app_dir,launch_args
        from dashboard import Dashboard
        from mac_identity import database
        from local_ports import LocalPortWindow,BASE
        from conflict_window import ConflictWindow
        from inventory import Inventory
        from home import Home
        result['frozen']=bool(getattr(sys,'frozen',False));result['vendor_entries']=len(database())
        result['powershell_helper']=(BASE/'local_ports.ps1').is_file()
        result['elevation_arguments']=launch_args('--topology')
        root=tk.Tk();root.withdraw()
        ui=Dashboard(tk.Toplevel(root),None,startup=False)
        a=ui.model.add('192.0.2.1',name='Packaging smoke fixture',category='电脑');ui.selected=a['id'];ui.draw();ui.show_details()
        popup=ConflictWindow(ui,lambda *args:'');popup.close()
        with tempfile.TemporaryDirectory(dir=output.parent) as folder:
            path=Path(folder)/'fixture.json';ui.model.save(path)
            result['asset_roundtrip']=len(Inventory.load(path).assets)==1
        result['icon_rendered']=bool(ui.canvas.find_withtag('icon:computer'))
        ui.model.dirty=False;ui.close()
        with patch.object(LocalPortWindow,'submit'):
            manager=LocalPortWindow(root);manager.close()
        Home(tk.Toplevel(root),None,None,None)
        root.update_idletasks();root.destroy()
        result['ok']=all([result['frozen'],result['powershell_helper'],result['vendor_entries']>58000,result['asset_roundtrip'],result['icon_rendered']])
    except Exception:
        import traceback
        result['ok']=False;result['error']=traceback.format_exc()
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
