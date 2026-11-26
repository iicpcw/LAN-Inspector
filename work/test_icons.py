import sys,unittest
from unittest.mock import MagicMock
from html.parser import HTMLParser
sys.path.insert(0,'outputs/LAN-Inspector')
import dashboard as d
from device_icons import icon_kind
import discovery

class Tests(unittest.TestCase):
    def test_conservative_categories(self):
        for category,kind in [('Windows 终端/服务器','computer'),('Linux 终端','computer'),('本机 Windows','computer'),('疑似 Android 设备','phone'),('手机','phone'),('平板','tablet'),('服务器','server'),('交换机','switch'),('路由器','router'),('防火墙','firewall'),('打印机','printer'),('未知设备','unknown'),('Apple, Inc.','unknown')]:
            self.assertEqual(icon_kind(category),kind,category)
    def test_icon_selection_details_and_no_mac_on_map(self):
        root=d.tk.Tk();root.withdraw();ui=d.Dashboard(root,lambda *a:None,startup=False)
        asset=ui.model.add('192.168.4.8',name='财务电脑',category='Windows 终端',mac='00:11:22:33:44:55',note='测试备注')
        ui.draw()
        self.assertTrue(ui.canvas.find_withtag('icon:computer'))
        visible=[ui.canvas.itemcget(i,'text') for i in ui.canvas.find_all() if ui.canvas.type(i)=='text']
        self.assertNotIn('00:11:22:33:44:55',visible)
        ui.press(MagicMock(x=asset['x']+139,y=asset['y']+35))
        self.assertEqual(ui.selected,asset['id'])
        self.assertIn('00:11:22:33:44:55',ui.details.get('1.0','end'))
        self.assertIn('测试备注',ui.details.get('1.0','end'))
        ui.scale(.6)
        self.assertTrue(ui.canvas.find_withtag('icon:computer'))
        root.destroy()
    def test_html_nodes_open_matching_details(self):
        rows=[dict(ip='192.168.4.8',status='在线',device_type='Android 手机',ports='',mac='00:11:22:33:44:55')]
        text=discovery.topology_html(rows,'192.168.4.0/24')
        self.assertIn('<details id="device-192-168-4-8">',text)
        self.assertIn('href="#device-192-168-4-8"',text)
        self.assertIn('.open=true',text)
        self.assertIn('00:11:22:33:44:55',text)
        self.assertNotIn('<details open',text)
        HTMLParser().feed(text)
unittest.main()
