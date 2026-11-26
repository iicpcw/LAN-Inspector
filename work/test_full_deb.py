import runpy
from unittest.mock import patch
build=runpy.run_path('work/build_full_deb.py')
def module(name):
 ns={'__name__':'check'}
 exec(build['data']['usr/share/lan-inspector/'+name+'.py'].decode('utf-8-sig'),ns)
 return ns
m=module('linux_ports')
with patch('subprocess.check_output',return_value='tcp LISTEN 0 16 127.0.0.1:8080 0.0.0.0:* users:(("test",pid=123,fd=5))'):
 r=m['run_action']('scan')['data']['endpoints'][0]
 assert (r['port'],r['process'],r['pid'])==(8080,'test','123')
