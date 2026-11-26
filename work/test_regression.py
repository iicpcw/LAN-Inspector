import sys, threading, unittest
from unittest.mock import patch, MagicMock
sys.path.insert(0, 'outputs/LAN-Inspector')
import lan_inspector as m

class Regression(unittest.TestCase):
    def probe(self, alive, address, code=10061):
        sock=MagicMock(); sock.__enter__.return_value=sock; sock.connect_ex.return_value=code; sock.recv.return_value=b''
        with patch.object(m,'ping',return_value=alive), patch.object(m,'mac',return_value=address), patch.object(m.socket,'socket',return_value=sock):
            return m.inspect('192.168.1.99',[80],.2,threading.Event())
    def test_proxy_arp_subnet(self):
        rows=[self.probe(False,'AA:BB:CC:DD:EE:FF') for _ in range(254)]
        self.assertTrue(all(r['status']=='仅 ARP 响应' for r in rows))
        self.assertEqual(sum(r['status']=='在线' for r in rows),0)
    def test_no_reply(self):
        self.assertEqual(self.probe(False,'')['status'],'未确认')
    def test_real_icmp(self):
        self.assertEqual(self.probe(True,'')['status'],'在线')
    def test_real_tcp(self):
        self.assertEqual(self.probe(False,'',0)['status'],'在线')
    def test_ping_output(self):
        ip='192.168.1.99'
        self.assertTrue(m.valid_ping_reply(b'Reply from 192.168.1.99: bytes=32 time<1ms TTL=64',ip))
        self.assertFalse(m.valid_ping_reply(b'Reply from 192.168.1.1: Destination host unreachable.',ip))
        self.assertFalse(m.valid_ping_reply(b'Reply from 192.168.1.199: bytes=32 time<1ms TTL=64',ip))
        self.assertFalse(m.valid_ping_reply(b'Pinging 192.168.1.99\nReply from 192.168.1.1: bytes=32 TTL=64',ip))
    def test_duplicate_mac_ui(self):
        root=m.tk.Tk(); root.withdraw()
        app=m.App(root)
        for ip in ['192.168.1.2','192.168.1.3']:
            row=self.probe(False,'AA:BB:CC:DD:EE:FF'); row['ip']=ip
            app.events.put(('row',row))
        app.poll()
        self.assertTrue(all('代理 ARP' in r['warning'] for r in app.rows))
        root.destroy()

if __name__=='__main__': unittest.main()
