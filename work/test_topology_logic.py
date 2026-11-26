import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,'outputs/LAN-Inspector')
import dashboard as d
class LogicTests(unittest.TestCase):
 def setUp(self):
  self.root=d.tk.Tk();self.root.withdraw();self.ui=d.Dashboard(self.root,lambda *a:None,startup=False)
  self.temp=tempfile.TemporaryDirectory(dir='work');self.ui.file=Path(self.temp.name)/'inventory.json'
 def tearDown(self):self.root.destroy();self.temp.cleanup()
 def test_scope_and_overlap(self):
  u=self.ui;a=u.model.add('192.168.1.8',name='manual');b=u.model.add('192.168.4.8')
  u.view_networks=['192.168.4.0/24','192.168.4.8/32'];nets=u.visible_networks()
  self.assertFalse(u.visible_group(a,nets[0],nets));self.assertFalse(u.visible_group(b,nets[0],nets));self.assertTrue(u.visible_group(b,nets[1],nets))
  u.show_all.set(True);self.assertEqual(u.visible_networks(),u.model.networks);self.assertEqual(a['name'],'manual')
 def test_clear_backup_and_reload(self):
  u=self.ui;u.model.add('192.168.4.8',name='manual');u.target.set('192.168.4.0/24');u.timer=self.root.after(60000,lambda:None)
  with patch.object(d.messagebox,'askyesno',return_value=True):u.clear_topology()
  self.assertFalse(u.model.assets);self.assertIsNone(u.timer);self.assertFalse(u.refresh.get());self.assertFalse(d.Inventory.load(u.file).assets)
  backups=list(u.file.parent.glob('*backup*.json'));self.assertEqual(len(backups),1);self.assertEqual(d.Inventory.load(backups[0]).find('192.168.4.8')['name'],'manual')
 def test_clear_cancel_busy_and_failed_backup(self):
  u=self.ui;u.model.add('192.168.4.8')
  with patch.object(d.messagebox,'askyesno',return_value=False):u.clear_topology()
  self.assertEqual(len(u.model.assets),1)
  u.pinging=True
  with patch.object(d.messagebox,'showinfo'),patch.object(d.messagebox,'askyesno') as ask:u.clear_topology();ask.assert_not_called()
  u.pinging=False
  with patch.object(d.messagebox,'askyesno',return_value=True),patch.object(d.messagebox,'showerror'),patch.object(u.model,'save',side_effect=OSError('test')):u.clear_topology()
  self.assertEqual(len(u.model.assets),1)
 def test_stop_disables_refresh(self):
  u=self.ui;u.timer=self.root.after(60000,lambda:None);u.stop_scan();self.assertTrue(u.stop.is_set());self.assertIsNone(u.timer);self.assertFalse(u.refresh.get())
unittest.main()
