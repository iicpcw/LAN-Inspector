import sys, unittest, threading
from unittest.mock import patch
sys.path.insert(0,'outputs/LAN-Inspector')
import mac_identity as m
import discovery as d
import lan_inspector as app
class Tests(unittest.TestCase):
    def test_longest_prefix(self):
        db={'001122':('MA-L','Parent'),'0011223':('MA-M','Medium'),'001122334':('MA-S','Small')}
        self.assertEqual(m.lookup('00:11:22:33:44:55',db)['mac_vendor'],'Small')
        self.assertEqual(m.lookup('00:11:22:3F:44:55',db)['mac_vendor'],'Medium')
        self.assertEqual(m.lookup('00:11:22:FF:44:55',db)['mac_vendor'],'Parent')
    def test_local_mac_not_brand(self):
        r=m.lookup('02:11:22:33:44:55',{'021122':('MA-L','Apple')})
        self.assertEqual(r['mac_vendor'],'')
        self.assertIn('本地管理',r['mac_scope'])
    def test_invalid(self):
        for address in ('', 'bad', '00:00:00:00:00:00','FF:FF:FF:FF:FF:FF','01:00:5E:00:00:01'):
            self.assertFalse(m.lookup(address,{})['mac_vendor'])
    def test_apple_not_iphone(self):
        r=m.lookup('00:11:22:33:44:55',{'001122':('MA-L','Apple, Inc.')})
        self.assertIn('不能确定 iOS',r['device_hint'])
    def test_real_database(self):
        db=m.database()
        self.assertGreater(len(db),58000)
        for organization in ('apple','samsung','huawei','xiaomi'):
            matches=[(prefix,org) for prefix,(_,org) in db.items() if organization in org.lower() and not int(prefix[:2],16)&3]
            self.assertTrue(matches,organization)
            prefix,org=max(matches,key=lambda pair:len(pair[0]))
            self.assertTrue(m.lookup(prefix.ljust(12,'0'))['mac_vendor'])
    def test_shared_mac(self):
        rows=[dict(ip=ip,mac='00:11:22:33:44:55',warning='',device_hint='Apple') for ip in ['1.1.1.1','1.1.1.2']]
        m.mark_shared_mac(rows,'00:11:22:33:44:55')
        self.assertTrue(all('不能归属' in r['device_hint'] for r in rows))
    def test_mobile_service_and_cisco(self):
        self.assertEqual(d.classify([80],{'80':'Android/12'})[0],'疑似 Android 设备')
        self.assertEqual(d.classify([80],{'80':'iPhone OS 17_0'})[0],'疑似 iOS/iPadOS 移动设备')
        self.assertEqual(d.classify([80],{'80':'iPhone OS 17_0'})[1],'低')
        self.assertNotIn('iOS',d.classify([80],{'80':'Cisco IOS Software'})[0])
    def test_graph_vendor_and_columns(self):
        row=dict(ip='192.168.1.2',status='在线',mac='00:11:22:33:44:55',ports='',device_type='未知设备')
        row.update(m.lookup(row['mac'],{'001122':('MA-L','Apple, Inc.')}))
        text=d.topology_html([row],'192.168.1.0/24')
        self.assertIn('Apple, Inc.',text)
        self.assertIn('不能确定 iOS',text)
        self.assertEqual(text.count('<th>'),text.count('<td>'))
    def test_scan_populates_vendor_and_ui(self):
        with patch.object(app,'ping',return_value=True),patch.object(app,'mac',return_value='02:11:22:33:44:55'):
            row=app.inspect('127.0.0.1',[],.1,threading.Event(),False,[])
        self.assertIn('本地管理',row['mac_scope'])
        root=app.tk.Tk();root.withdraw();ui=app.App(root)
        ui.events.put(('row',row));ui.poll()
        self.assertIn('mac_vendor',ui.table['columns'])
        self.assertEqual(len(ui.table.item('127.0.0.1','values')),len(ui.table['columns']))
        root.destroy()
unittest.main()
