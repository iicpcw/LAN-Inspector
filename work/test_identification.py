import sys, threading, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, 'outputs/LAN-Inspector')
import lan_inspector as app
import discovery as d

class IdentificationTests(unittest.TestCase):
    def test_product_types(self):
        for text, expected in [('FortiGate','防火墙'),('Cisco Catalyst','交换机'),('MikroTik RouterOS','路由器'),('Microsoft-IIS/10','Windows 终端/服务器'),('SSH-2.0-OpenSSH Ubuntu','Linux 终端/服务器')]:
            kind, confidence, reason = d.classify([80], {'80':text})
            self.assertEqual(kind,expected)
            self.assertEqual(confidence,'中')
    def test_ssh_is_not_linux(self):
        self.assertEqual(d.classify([22],{'22':'SSH-2.0-OpenSSH_9.2'})[0], 'SSH 设备（类型未知）')
    def test_conflicting_fingerprints(self):
        self.assertEqual(d.classify([22,80],{'22':'Ubuntu','80':'FortiGate'})[0], '防火墙')
    def test_port_only_low_confidence(self):
        self.assertEqual(d.classify([135,445],{})[1],'低')
        self.assertEqual(d.classify([80],{})[0],'未知设备')
    def test_cancel_no_banner(self):
        stop=threading.Event(); stop.set()
        with patch.object(d,'read_banner') as read:
            d.identify('127.0.0.1',[80],.1,stop)
            read.assert_not_called()
    def test_offline_graph_escape(self):
        rows=[dict(ip='192.168.1.2',status='仅 ARP 响应',mac='AA',ports='',device_type='<script>alert(1)</script>',confidence='未知',fingerprint='a&b',warning='代理 ARP'),dict(ip='192.168.1.3',status='未确认')]
        text=d.topology_html(rows,'192.168.1.0/24')
        self.assertIn('&lt;script&gt;',text)
        self.assertNotIn('<script>',text)
        self.assertIn('不表示物理连线',text)
        self.assertIn('stroke-dasharray',text)
        self.assertEqual(text.count('<g>'),1)
        with tempfile.TemporaryDirectory(dir='work') as folder:
            self.assertTrue(d.save_topology(rows,'192.168.1.0/24',folder).exists())
    def test_auto_generate_on_done(self):
        root=app.tk.Tk(); root.withdraw(); ui=app.App(root)
        ui.scan_target='127.0.0.1'
        ui.rows=[dict(ip='127.0.0.1',status='在线',mac='',ports='80',device_type='未知设备',confidence='未知',fingerprint='',warning='')]
        with tempfile.TemporaryDirectory(dir='work') as folder:
            fake=Path(folder)/'topology.html'
            with patch.object(app,'save_topology',return_value=fake) as save:
                ui.events.put(('done',None)); ui.poll()
                save.assert_called_once()
                self.assertEqual(ui.report_path,fake)
        root.destroy()

unittest.main()
