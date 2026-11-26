import sys, unittest, threading
from unittest.mock import patch, MagicMock
from html.parser import HTMLParser
sys.path.insert(0,'outputs/LAN-Inspector')
import port_policy as p
import lan_inspector as m
import discovery as d
class Tests(unittest.TestCase):
    def test_four_required(self):
        r=p.assess([22,80,135,443],[22,80,135,443],[22,80,135,443])
        self.assertEqual(r['audit_status'],'常见高危端口未封堵')
        self.assertEqual(r['risk_ports'],'22,80,135,443')
    def test_custom(self):
        self.assertEqual(p.assess([443,445],[443,445],[445])['risk_ports'],'445')
    def test_timeout_not_compliant(self):
        r=p.assess([],[22,80],[22,80])
        self.assertEqual(r['audit_status'],'未发现策略端口可连接')
        self.assertIn('不能证明已封堵',r['audit_detail'])
    def test_not_scanned(self):
        self.assertEqual(p.assess([],[],[22])['audit_status'],'检查不完整')
    def test_partial_and_errors(self):
        r=p.assess([22],[22,80],[22,80,443],[80])
        self.assertEqual(r['risk_ports'],'22')
        self.assertEqual(r['unchecked_policy_ports'],'80,443')
    def test_disabled(self):
        self.assertEqual(p.assess([22],[22],[])['audit_status'],'未配置封堵规则')
    def test_scan_and_red_ui_and_report(self):
        sock=MagicMock();sock.__enter__.return_value=sock;sock.connect_ex.return_value=0
        with patch.object(m,'ping',return_value=False),patch.object(m,'mac',return_value=''),patch.object(m.socket,'socket',return_value=sock):
            row=m.inspect('127.0.0.1',[22,443],.1,threading.Event(),False,[22,443])
        root=m.tk.Tk();root.withdraw();app=m.App(root)
        app.events.put(('row',row));app.poll()
        self.assertIn('risk',app.table.item('127.0.0.1','tags'))
        root.destroy()
        text=d.topology_html([row],'127.0.0.1')
        self.assertIn('stroke="#b42318"',text)
        self.assertIn('常见高危端口未封堵',text)
        self.assertEqual(text.count('<th>'),text.count('<td>'))
        self.assertIn('22,443',text)
unittest.main()
