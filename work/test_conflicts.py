import sys,unittest,threading,tempfile,time
from pathlib import Path
from unittest.mock import patch,MagicMock
sys.path.insert(0,'outputs/LAN-Inspector')
from ip_conflict import sample,apply,acknowledge
from inventory import Inventory
import dashboard as d
from conflict_window import ConflictWindow
A='00:11:22:33:44:55';B='00:11:22:33:44:66'
def result(values,source='192.168.31.8',t=100):
    return dict(ip='192.168.31.9',source_ip=source,samples=[dict(mac=m,time=t) for m in values],errors=[],cancelled=False)
class Tests(unittest.TestCase):
    def test_same_round_different_mac(self):
        asset={};r=apply(asset,result([A,B]),100)
        self.assertEqual(r['state'],'疑似 IP 冲突');self.assertTrue(asset['conflict_alert'])
    def test_history_change_not_simultaneous_proof(self):
        asset={};apply(asset,result([A]),100);r=apply(asset,result([B],t=110),110)
        self.assertEqual(r['state'],'IP–MAC 变化，需核实')
    def test_same_mac_not_no_conflict(self):
        r=apply({},result([A,A]),100);self.assertIn('不代表无冲突',r['reason'])
    def test_different_interface_not_combined(self):
        asset={};apply(asset,result([A]),100);r=apply(asset,result([B],source='192.168.31.18',t=110),110)
        self.assertNotIn('conflict_alert',asset)
    def test_no_response_does_not_clear_old_alert(self):
        asset={};apply(asset,result([A,B]),100);apply(asset,result([],t=110),110)
        self.assertIn('conflict_alert',asset)
    def test_old_or_future_record_not_used(self):
        asset={};apply(asset,result([A],t=100),100);apply(asset,result([B],t=1000),1000)
        self.assertNotIn('conflict_alert',asset)
    def test_clear_retains_history(self):
        asset={};apply(asset,result([A,B]),100)
        with patch('ip_conflict.time.time',return_value=101):acknowledge(asset)
        apply(asset,result([B],t=102),102)
        self.assertNotIn('conflict_alert',asset);self.assertTrue(asset['conflict_events'])
    def test_samples_stop_and_interface(self):
        stop=threading.Event();resolver=MagicMock(side_effect=[A,B,A])
        with patch.object(stop,'wait',return_value=False):r=sample('192.168.31.9','192.168.31.8',resolver,stop)
        self.assertEqual(len(r['samples']),3);resolver.assert_called_with('192.168.31.9','192.168.31.8')
        stop.set();resolver.reset_mock();sample('192.168.31.9','192.168.31.8',resolver,stop);resolver.assert_not_called()
    def test_save_evidence(self):
        model=Inventory();asset=model.add('192.168.31.9');apply(asset,result([A,B]),100)
        with tempfile.TemporaryDirectory(dir='work') as folder:
            path=Path(folder)/'assets.json';model.save(path);restored=Inventory.load(path).find(asset['ip'])
            self.assertEqual(restored['conflict_alert']['macs'],[A,B]);self.assertEqual(len(restored['mac_observations']),2)
    def test_subfeature_updates_map_without_claiming_online(self):
        root=d.tk.Tk();root.withdraw();ui=d.Dashboard(root,None,startup=False)
        ui.adapters=[dict(name='WLAN',ip='192.168.31.8',network='192.168.31.0/24')]
        ui.adapter_combo.configure(values=['WLAN']);ui.adapter_combo.current(0)
        popup=ConflictWindow(ui,MagicMock());popup.network='192.168.31.0/24';popup.checked=0;popup.total=1
        with patch.object(ui,'save'):
            popup.events.put(('row',result([A,B])));popup.events.put(('done',None));popup.poll()
        asset=ui.model.find('192.168.31.9');self.assertEqual(ui.model.label(asset),'仅 ARP 响应');self.assertTrue(asset['conflict_alert'])
        ui.selected=asset['id'];ui.show_details();self.assertIn(A,ui.details.get('1.0','end'))
        colors=[ui.canvas.itemcget(i,'outline') for i in ui.canvas.find_all() if ui.canvas.type(i) in ('rectangle','oval','polygon')]
        self.assertIn('#9c2780',colors)
        popup.close();root.destroy()
    def test_remote_rejected(self):
        root=d.tk.Tk();root.withdraw();ui=d.Dashboard(root,None,startup=False)
        ui.adapters=[dict(name='WLAN',ip='192.168.31.8',network='192.168.31.0/24')]
        ui.adapter_combo.configure(values=['WLAN']);ui.adapter_combo.current(0)
        resolver=MagicMock();popup=ConflictWindow(ui,resolver);popup.target.set('192.168.4.9')
        with patch('conflict_window.messagebox.showerror') as error:
            popup.run();error.assert_called_once();resolver.assert_not_called()
        popup.close();root.destroy()
unittest.main()
