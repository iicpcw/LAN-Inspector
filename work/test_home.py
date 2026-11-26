import sys, unittest
from unittest.mock import patch, MagicMock
sys.path.insert(0,'outputs/LAN-Inspector')
import home
class Tests(unittest.TestCase):
    def test_open_topology_and_reuse_window(self):
        root=home.tk.Tk();root.withdraw()
        app=home.Home(root,MagicMock(),MagicMock(),MagicMock())
        with patch('dashboard.Dashboard') as create:
            app.open_topology();first=app.windows['topology'][0]
            app.open_topology();create.assert_called_once()
            self.assertIs(first,app.windows['topology'][0])
        root.destroy()
    def test_open_other_tools(self):
        root=home.tk.Tk();root.withdraw();scanner=MagicMock();local=MagicMock()
        local.return_value.win=home.tk.Toplevel(root)
        app=home.Home(root,MagicMock(),scanner,local)
        app.open_scanner();app.open_local()
        scanner.assert_called_once();local.assert_called_once_with(root)
        root.destroy()
    def test_close_protects_active_operation(self):
        root=home.tk.Tk();root.withdraw();app=home.Home(root,None,None,None)
        window=home.tk.Toplevel(root);controller=MagicMock(busy=True,running=False)
        app.windows['local']=(window,controller)
        with patch.object(home.messagebox,'showinfo') as notify:
            app.close();notify.assert_called_once();self.assertTrue(root.winfo_exists())
        root.destroy()
unittest.main()
