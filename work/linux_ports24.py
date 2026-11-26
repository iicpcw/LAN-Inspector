import json
import os
from pathlib import Path
import re
import subprocess

def run_action(action,items=()):
    if action in ('block','remove'):
        args=['/usr/bin/python3','-I','/usr/share/lan-inspector/linux_firewall.py',action]
        if os.geteuid():args=['/usr/bin/pkexec']+args
        subprocess.run(args,input=json.dumps(items),text=True,check=True)
    text=subprocess.check_output(['ss','-H','-lntup'],text=True,timeout=10)
    endpoints=[]
    for line in text.splitlines():
        parts=line.split(None,6)
        if len(parts)<6:continue
        proto,state,_,_,local,_=parts[:6]
        address,port=local.rsplit(':',1)
        if not port.isdecimal():continue
        for name,pid in re.findall(r'"([^"]+)",pid=(\d+)',line) or [('', '')]:
            endpoints.append(dict(protocol=proto.upper(),state=state,address=address,port=int(port),process=name,pid=pid))
    path=Path('/var/lib/lan-inspector/ports.json')
    rules=[]
    for item in json.loads(path.read_text()) if path.exists() else []:
        proto,port=item['protocol'],item['port']
        rules.append(dict(item,name=f'LANInspector.LocalPortBlock.v1.{proto}.{port}',enabled='已配置',activeStore=False,direction='入站',action='DROP',profile='IPv4 / 可用 IPv6'))
    return dict(data=dict(endpoints=endpoints,rules=rules,warnings=[]),results=[])
