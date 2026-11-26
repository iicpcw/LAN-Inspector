import sys,json,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
sys.path.insert(0,'outputs/LAN-Inspector')
from inventory import Inventory
import dashboard as d
import network_tools as n
import lan_inspector as scanner

class ModelTests(unittest.TestCase):
    def test_multiple_subnets_and_limit(self):
        m=Inventory();self.assertEqual(len(m.add_networks('192.168.192.0/24 192.168.4.0/24')),508)
        for value in ['192.0/24','4.0/24','192.168.0.0/16']:
            with self.assertRaises(ValueError):m.add_networks(value)
    def test_user_edits_preserved(self):
        m=Inventory();m.add_networks('192.168.4.0/24')
        a=m.add('192.168.4.8',name='仓库终端',category='Android',mac='00:11:22:33:44:55',note='手工台账')
        m.observe(dict(ip=a['ip'],status='在线',device_type='未知设备',mac='AA:BB:CC:DD:EE:FF',hostname='dns-name'))
        self.assertEqual(m.displayed(a)['name'],'仓库终端');self.assertEqual(m.displayed(a)['category'],'Android')
        self.assertEqual(m.displayed(a)['mac'],'00:11:22:33:44:55')
        m.observe(dict(ip=a['ip'],status='未确认'))
        self.assertIn(a['id'],m.assets);self.assertEqual(m.label(a),'未确认（曾在线）')
    def test_do_not_create_unresponsive_assets(self):
        m=Inventory();self.assertIsNone(m.observe(dict(ip='192.168.4.8',status='未确认')))
    def test_manual_offline(self):
        m=Inventory();a=m.add('192.168.4.8',manual_state='离线（手工）')
        m.observe(dict(ip=a['ip'],status='在线'))
        self.assertEqual(m.label(a),'离线（手工）')
    def test_save_reload_layout_stale(self):
        m=Inventory();m.add_networks('192.168.4.0/24');a=m.add('192.168.4.8',name='test');a.update(x=130,y=280)
        m.observe(dict(ip=a['ip'],status='在线'))
        with tempfile.TemporaryDirectory(dir='work') as folder:
            p=Path(folder)/'assets.json';m.save(p);loaded=Inventory.load(p)
            b=loaded.find(a['ip']);self.assertEqual(b['id'],a['id']);self.assertEqual(b['x'],130)
            self.assertEqual(loaded.label(b),'待刷新（历史记录）');self.assertEqual(loaded.target_text,'192.168.4.0/24')
    def test_duplicate_and_membership(self):
        m=Inventory();m.add('192.168.4.8')
        with self.assertRaises(ValueError):m.add('192.168.4.8')
        with self.assertRaises(ValueError):m.add('192.168.4.9',network='192.168.192.0/24')
    def test_ptr_fallback(self):
        m=Inventory();a=m.observe(dict(ip='192.168.4.8',status='在线',hostname='mobile.internal'))
        self.assertEqual(m.displayed(a)['name'],'mobile.internal')

class NetworkTests(unittest.TestCase):
    def test_latency_exact_ip(self):
        replies=[b'Reply from 192.168.4.8: bytes=32 time=4ms TTL=64',b'Reply from 192.168.4.8: bytes=32 time<1ms TTL=64',b'Reply from 192.168.4.1: Destination host unreachable.',b'Request timed out.']
        with patch.object(n.subprocess,'run',side_effect=[MagicMock(returncode=0,stdout=x) for x in replies]),patch.object(n.time,'sleep'):
            r=n.latency('192.168.4.8')
        self.assertEqual(r['received'],2);self.assertEqual(r['loss'],50);self.assertEqual(r['average'],2.25)
    def test_cross_network_skips_arp(self):
        with patch.object(scanner,'ping',return_value=False),patch.object(scanner,'mac') as mac:
            r=scanner.inspect('192.168.4.8',[],.1,threading.Event(),False,[],False)
            mac.assert_not_called();self.assertEqual(r['mac'],'');self.assertEqual(r['status'],'未确认')
    def test_latency_cancel(self):
        stop=threading.Event();stop.set()
        with patch.object(n.subprocess,'run') as run:
            r=n.latency('192.168.4.8',stop);run.assert_not_called();self.assertEqual(r['sent'],0)

class UiTests(unittest.TestCase):
    def test_cross_scan_merge_and_save(self):
        calls=[]
        def probe(ip,selected,timeout,stop,fingerprint,resolve_mac=True):
            calls.append((ip,resolve_mac))
            return dict(ip=ip,status='在线',mac='',device_type='未知设备',ports='80')
        root=d.tk.Tk();root.withdraw();ui=d.Dashboard(root,probe,startup=False)
        with tempfile.TemporaryDirectory(dir='work') as folder:
            ui.file=Path(folder)/'inventory.json';ui.refresh.set(False)
            ui.adapters=[dict(ip='192.168.192.8',network='192.168.192.0/24')]
            ui.target.set('192.168.4.8/32');ui.model.add('192.168.192.99',name='手工离线设备',manual_state='离线（手工）',network='192.168.192.0/24')
            with patch.object(d,'reverse_name',return_value='remote.test'),patch.object(d.MacContext,'refresh'):
                ui.scan()
                deadline=time.monotonic()+3
                while ui.running and time.monotonic()<deadline:root.update();time.sleep(.02)
            self.assertFalse(ui.running);self.assertEqual(calls,[('192.168.4.8',False)])
            self.assertEqual(len(ui.model.assets),2);self.assertTrue(ui.file.exists())
            a=ui.model.find('192.168.4.8');self.assertEqual(ui.model.displayed(a)['name'],'remote.test')
            ui.selected=a['id'];ui.show_details();self.assertIn('remote.test',ui.details.get('1.0','end'))
            ui.scale(1.15);self.assertAlmostEqual(ui.zoom,1.15)
        root.destroy()
    def test_drag_preserves_model_coordinates(self):
        root=d.tk.Tk();root.withdraw();ui=d.Dashboard(root,lambda *a:None,startup=False)
        a=ui.model.add('192.168.4.8');ui.draw();ui.selected=a['id'];ui.drag=(10,10)
        before=a['x'];e=MagicMock(x=30,y=30);ui.motion(e)
        self.assertEqual(a['x'],before+20);self.assertTrue(ui.model.dirty)
        root.destroy()

unittest.main()
