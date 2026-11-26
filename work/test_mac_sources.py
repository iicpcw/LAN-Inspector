import sys,struct,threading,unittest
from unittest.mock import patch,MagicMock
sys.path.insert(0,'outputs/LAN-Inspector')
import mac_sources as m
A='00:11:22:33:44:55';B='00:11:22:33:44:66'
ADAPTER=dict(name='Ethernet',ip='192.168.31.8',network='192.168.31.0/24',interface_index=7,mac=A)
def row(ip='192.168.31.9'):return dict(ip=ip,status='未确认',ports='',device_type='未知设备')
def cache(mac=A,index=7,state='Stale'):return dict(ip='192.168.31.9',mac=mac,interface_index=index,state=state,source='Windows 邻居表')
def packet(tid=123,mac=A):
    payload=b'\x01'+b'TESTPC         '+b'\x00'+b'\x00\x00'+bytes.fromhex(mac.replace(':',''))+b'\0'*40
    return struct.pack('!6H',tid,0x8400,0,1,0,0)+b'\xc0\x0c'+struct.pack('!HHIH',0x21,1,0,len(payload))+payload
class Tests(unittest.TestCase):
    def test_own_mac_no_network(self):
        context=m.MacContext([ADAPTER])
        with patch.object(m,'active_arp') as arp:
            result=context.resolve(ADAPTER['ip'],threading.Event());arp.assert_not_called()
        self.assertEqual(result['mac'],A);self.assertEqual(result['mac_source'],'本机网卡配置')
    def test_arp_uses_source_and_retries(self):
        context=m.MacContext([ADAPTER]);stop=threading.Event()
        with patch.object(m,'active_arp',side_effect=['',A]) as arp,patch.object(stop,'wait',return_value=False):
            result=context.resolve('192.168.31.9',stop,retry=True)
            self.assertEqual(arp.call_count,2);arp.assert_called_with('192.168.31.9',ADAPTER['ip'])
        self.assertEqual(result['mac'],A)
    def test_cache_fallback_not_online(self):
        context=m.MacContext([ADAPTER]);context.cache=[cache()]
        result=context.enrich(row(),threading.Event(),active=False)
        self.assertEqual(result['mac'],A);self.assertEqual(result['status'],'仅缓存记录')
    def test_wrong_interface_and_remote_rejected(self):
        context=m.MacContext([ADAPTER]);context.cache=[cache(index=9)]
        self.assertEqual(context.resolve('192.168.31.9',threading.Event(),active=False)['mac'],'')
        with patch.object(m,'active_arp') as arp,patch.object(m,'netbios_mac') as nb:
            r=context.resolve('192.168.4.9',threading.Event(),netbios=True);arp.assert_not_called();nb.assert_not_called()
            self.assertEqual(r['mac'],'')
    def test_overlapping_virtual_interfaces_require_selection(self):
        second=dict(ADAPTER,name='Virtual',ip='192.168.31.18',interface_index=9)
        context=m.MacContext([ADAPTER,second]);self.assertIsNone(context.adapter('192.168.31.9')[0])
        context.preferred_source=second['ip'];self.assertEqual(context.adapter('192.168.31.9')[0]['interface_index'],9)
    def test_disagreeing_cache_not_silently_chosen(self):
        context=m.MacContext([ADAPTER]);context.cache=[cache(A),dict(cache(B),source='arp -a 缓存')]
        r=context.resolve('192.168.31.9',threading.Event(),active=False)
        self.assertEqual(r['mac'],'');self.assertEqual(r['mac_state'],'来源不一致，待核实')
    def test_active_vs_old_cache_is_explained(self):
        context=m.MacContext([ADAPTER]);context.cache=[cache(B)]
        with patch.object(m,'active_arp',return_value=A):r=context.resolve('192.168.31.9',threading.Event())
        self.assertEqual(r['mac'],A);self.assertEqual(len(r['mac_candidates']),2);self.assertIn('不能直接判定',r['mac_note'])
    def test_arp_localized_interface_header(self):
        text='接口: 192.168.31.8 --- 0x7\n 192.168.31.9 00-11-22-33-44-55 动态\n接口: 172.16.0.8 --- 0x9\n 192.168.31.9 00-11-22-33-44-66 dynamic\n 224.0.0.1 01-00-5e-00-00-01 static'
        parsed=m.parse_arp(text);self.assertEqual(len(parsed),2);self.assertEqual(parsed[0]['interface_index'],7);self.assertEqual(parsed[1]['interface_index'],9)
    def test_nbstat_checks_transaction_and_length(self):
        self.assertEqual(m.parse_nbstat(packet(),123),A)
        self.assertEqual(m.parse_nbstat(packet(),999),'')
        self.assertEqual(m.parse_nbstat(packet()[:22],123),'')
        self.assertEqual(m.parse_nbstat(packet(mac='00:00:00:00:00:00'),123),'')
    def test_nbstat_is_labelled_self_report(self):
        context=m.MacContext([ADAPTER])
        with patch.object(m,'active_arp',return_value=''),patch.object(m,'netbios_mac',return_value=A):
            result=context.enrich(row(),threading.Event(),netbios=True)
        self.assertEqual(result['status'],'仅设备自报 MAC');self.assertIn('NetBIOS',result['mac_source'])
    def test_netbios_rejects_wrong_peer(self):
        sock=MagicMock();sock.__enter__.return_value=sock;sock.recvfrom.return_value=(packet(),('192.168.31.99',137))
        with patch.object(m.socket,'socket',return_value=sock),patch.object(m.os,'urandom',return_value=struct.pack('!H',123)):
            self.assertEqual(m.netbios_mac('192.168.31.9',ADAPTER['ip']),'')
    def test_cancellation(self):
        context=m.MacContext([ADAPTER]);stop=threading.Event();stop.set()
        with patch.object(m,'active_arp') as arp:
            result=context.resolve('192.168.31.9',stop);arp.assert_not_called();self.assertEqual(result['mac'],'')
unittest.main()
