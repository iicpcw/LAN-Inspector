import sys,unittest,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,'outputs/LAN-Inspector')
from inventory import Inventory
import dashboard as d
from device_icons import icon_kind
class Tests(unittest.TestCase):
    def test_config_is_not_online(self):
        m=Inventory();a=m.record_gateway('192.168.31.1',dict(adapter='WLAN',local_ip='192.168.31.8'),'192.168.31.0/24')
        self.assertEqual(m.label(a),'未检测')
        self.assertIn('网关',m.displayed(a)['category'])
        self.assertEqual(icon_kind(m.displayed(a)['category']),'router')
        m.observe(dict(ip=a['ip'],status='未确认',device_type='未知设备'))
        self.assertEqual(m.label(a),'未确认');self.assertIn(a['id'],m.assets)
    def test_not_force_hardware_type(self):
        m=Inventory();a=m.record_gateway('192.168.31.1',{},'192.168.31.0/24')
        m.observe(dict(ip=a['ip'],status='在线',device_type='防火墙'))
        self.assertEqual(icon_kind(m.displayed(a)['category']),'firewall')
        a['category']='三层交换机'
        self.assertEqual(icon_kind(m.displayed(a)['category']),'switch')
    def test_outside_subnet_not_fabricated_membership(self):
        m=Inventory();a=m.record_gateway('10.1.1.1',{},'192.168.31.0/24')
        self.assertEqual(a['network'],'10.1.1.1/32')
        self.assertIsNone(m.record_gateway('0.0.0.0',{}))
    def test_saved_gateway_not_current_after_reload(self):
        m=Inventory();a=m.record_gateway('192.168.31.1',{},'192.168.31.0/24')
        with tempfile.TemporaryDirectory(dir='work') as folder:
            path=Path(folder)/'assets.json';m.save(path);loaded=Inventory.load(path)
            b=loaded.find(a['ip']);self.assertFalse(b['gateway_current']);self.assertIn('历史',loaded.displayed(b)['name'])
    def test_virtual_adapter_choice_and_gateway_kept(self):
        root=d.tk.Tk();root.withdraw();ui=d.Dashboard(root,lambda *a:None,startup=False)
        adapters=[dict(ip='172.22.0.1',network='172.22.0.0/24',name='Virtual',gateways=[]),dict(ip='192.168.31.8',network='192.168.31.0/24',name='WLAN',gateways=['192.168.31.1'])]
        ui.target.set('192.168.31.0/24')
        with patch.object(ui,'save'),patch.object(ui,'scan'):
            ui.accept_adapters(adapters)
        self.assertEqual(ui.adapter_combo.current(),1)
        self.assertIsNotNone(ui.model.find('192.168.31.1'))
        ui.adapter_combo.current(0);ui.choose_adapter();self.assertEqual(ui.target.get(),'172.22.0.0/24')
        ui.adapter_combo.current(1);ui.choose_adapter();self.assertEqual(ui.target.get(),'192.168.31.0/24')
        asset=ui.model.find('192.168.31.1');ui.selected=asset['id'];ui.draw();ui.show_details()
        self.assertIn('本机网卡配置',ui.details.get('1.0','end'))
        root.destroy()
unittest.main()
