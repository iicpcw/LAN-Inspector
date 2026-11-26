import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import MagicMock
sys.path.insert(0,'outputs/LAN-Inspector')
from fingerprint_engine import analyze
import discovery as d
from inventory import Inventory
from dashboard import Dashboard,tk
class Tests(unittest.TestCase):
    def test_web_body_keywords_not_os(self):
        response='HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>管理平台</title><script>Android Linux Ubuntu iPhone OS</script>'
        r=analyze([80],{'80':response});self.assertEqual(r['os_family'],'未知');self.assertEqual(r['device_type'],'未知设备')
    def test_router_and_linux_are_different_dimensions(self):
        r=analyze([22,80],{'22':'SSH-2.0-OpenSSH_9 Ubuntu','80':'HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n<title>小米路由器</title>'})
        self.assertEqual(r['device_type'],'路由器');self.assertEqual(r['os_family'],'Linux')
    def test_os_conflict_does_not_erase_hardware(self):
        r=analyze([22,80],{'22':'SSH-2.0-OpenSSH_for_Windows','80':'HTTP/1.1 200 OK\r\nServer: nginx (Ubuntu)\r\n\r\n<title>FortiGate</title>'})
        self.assertEqual(r['device_type'],'防火墙');self.assertIn('待核实',r['os_family'])
    def test_port_and_oui_not_os_proof(self):
        for port in (22,80,443,3389):self.assertEqual(analyze([port],{})['os_family'],'未知')
        self.assertEqual(analyze([135,445],{})['os_confidence'],'低')
    def test_title_windows_not_windows_os(self):
        r=analyze([80],{'80':'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Windows Android 下载</title>'})
        self.assertEqual(r['os_family'],'未知')
    def test_specific_products(self):
        for text,kind in [('MiWiFi','路由器'),('TP-Link Wireless Router','路由器'),('Synology DiskStation','NAS 设备'),('HP LaserJet','打印设备/打印服务')]:
            r=analyze([80],{'80':'HTTP/1.1 200 OK\r\n\r\n<title>'+text+'</title>'});self.assertEqual(r['device_type'],kind)
    def test_segmented_http_title(self):
        conn=MagicMock();conn.recv.side_effect=[b'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<ti',b'tle>MiWiFi</title>',b'']
        r=analyze([80],{'80':d.http_read(conn,'192.0.2.1')});self.assertEqual(r['device_type'],'路由器')
    def test_manual_os_saved_separately(self):
        model=Inventory();a=model.add('192.0.2.1',category='手机',os_override='Android')
        model.observe(dict(ip=a['ip'],status='在线',os_family='未知'))
        with tempfile.TemporaryDirectory(dir='work') as folder:
            file=Path(folder)/'assets.json';model.save(file);new=Inventory.load(file)
            self.assertEqual(new.displayed(new.find(a['ip']))['os_family'],'Android')
    def test_icon_only_map_keeps_details_on_click(self):
        root=tk.Tk();root.withdraw();ui=Dashboard(root,None,startup=False)
        a=ui.model.add('192.0.2.1',name='测试电脑',category='电脑',mac='00:11:22:33:44:55')
        ui.model.observe(dict(ip=a['ip'],status='在线',os_family='Windows',os_confidence='中'))
        ui.draw()
        labels=[ui.canvas.itemcget(i,'text') for i in ui.canvas.find_all() if ui.canvas.type(i)=='text']
        self.assertNotIn('00:11:22:33:44:55',labels);self.assertNotIn('Windows',labels);self.assertNotIn('在线',labels)
        ui.press(MagicMock(x=a['x']+139,y=a['y']+55));self.assertEqual(ui.selected,a['id'])
        self.assertIn('Windows',ui.details.get('1.0','end'));self.assertIn('00:11:22:33:44:55',ui.details.get('1.0','end'))
        root.destroy()
unittest.main()
