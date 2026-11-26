import sys,unittest,subprocess
from unittest.mock import patch,MagicMock
sys.path.insert(0,'outputs/LAN-Inspector')
import arp_cache as a
class Tests(unittest.TestCase):
    def setUp(self):self.adapter=dict(ip='192.168.31.8',network='192.168.31.0/24',interface_index=7,name='WLAN')
    def test_admin_required(self):
        with patch.object(a,'is_admin',return_value=False),patch.object(a.subprocess,'run') as run:
            with self.assertRaises(PermissionError):a.clear_cache(self.adapter,['192.168.31.9'])
            run.assert_not_called()
    def test_no_empty_scope_or_foreign_ip(self):
        with patch.object(a,'is_admin',return_value=True),patch.object(a,'local_networks',return_value=[self.adapter]),patch.object(a.subprocess,'run') as run:
            for targets in [[],['192.168.4.9']]:
                with self.assertRaises(ValueError):a.clear_cache(self.adapter,targets)
            run.assert_not_called()
    def test_targeted_command_keeps_interface_and_store(self):
        process=MagicMock(returncode=0,stdout=b'Ok')
        with patch.object(a,'is_admin',return_value=True),patch.object(a,'local_networks',return_value=[self.adapter]),patch.object(a.subprocess,'run',return_value=process) as run:
            results=a.clear_cache(self.adapter,['192.168.31.9'])
            args=run.call_args[0][0]
            for token in ['name=7','address=192.168.31.9','store=active']:self.assertIn(token,args)
            self.assertTrue(results[0]['success']);self.assertNotIn('shell',run.call_args[1])
    def test_whole_interface_requires_explicit_flag(self):
        process=MagicMock(returncode=0,stdout=b'Ok')
        with patch.object(a,'is_admin',return_value=True),patch.object(a,'local_networks',return_value=[self.adapter]),patch.object(a.subprocess,'run',return_value=process) as run:
            a.clear_cache(self.adapter,all_on_interface=True)
            args=run.call_args[0][0];self.assertIn('name=7',args);self.assertFalse(any(arg.startswith('address=') for arg in args))
    def test_stale_interface_rejected(self):
        with patch.object(a,'is_admin',return_value=True),patch.object(a,'local_networks',return_value=[]),patch.object(a.subprocess,'run') as run:
            with self.assertRaises(ValueError):a.clear_cache(self.adapter,['192.168.31.9'])
            run.assert_not_called()
    def test_timeout_not_reported_success(self):
        with patch.object(a,'is_admin',return_value=True),patch.object(a,'local_networks',return_value=[self.adapter]),patch.object(a.subprocess,'run',side_effect=subprocess.TimeoutExpired('test',20)):
            result=a.clear_cache(self.adapter,['192.168.31.9'])
            self.assertFalse(result[0]['success']);self.assertIn('未确认',result[0]['message'])
unittest.main()
