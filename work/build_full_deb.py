import io,tarfile,os,json
from pathlib import Path
src=Path('outputs/LAN-Inspector')
data={}
for p in src.iterdir():
 if p.suffix in ('.py','.csv') or p.name=='mac-vendors-source.json':data['usr/share/lan-inspector/'+p.name]=p.read_bytes()
def change(name,a,b):
 k='usr/share/lan-inspector/'+name
 s=data[k].decode('utf-8-sig');assert a in s;data[k]=s.replace(a,b).encode()
change('dashboard.py',"('IP 冲突检测',self.open_conflicts),",'')
change('dashboard.py','本机 Windows','本机 Linux')
change('dashboard.py','Windows（本机）','Linux（本机）')
change('app_paths.py','    return Path(sys.executable)',"    return Path(__import__('os').environ.get('XDG_DATA_HOME') or Path.home()/'.local/share')/'lan-inspector'\n    return Path(sys.executable)")
change('network_tools.py','    script = r"""','    from linux_native import adapters\n    return adapters()\n    script = r"""')
change('network_tools.py',"['nslookup','-timeout=1','-retry=1',ip]","['getent','hosts',ip]")
change('network_tools.py',"return match.group(1).rstrip('.')[:253] if match else ''","return text.split()[1][:253] if len(text.split())>1 else ''")
change('network_tools.py','creationflags=0x08000000','creationflags=0')
change('network_tools.py',"['ping','-n','1','-w','1000',ip]","['ping','-n','-c','1','-W','1',ip]")
change('network_tools.py',r'([=<])\s*(\d+)\s*ms',r'([=<])\s*(\d+(?:\.\d+)?)\s*ms')
change('network_tools.py',"int(m.group(2))","float(m.group(2))")
change('mac_sources.py','def cache_snapshot():','def cache_snapshot():\n    from linux_native import neighbors\n    return neighbors()')
change('mac_sources.py','def active_arp(ip,source_ip=None):','def active_arp(ip,source_ip=None):\n    return ""')
native='''import ipaddress
import json
import socket
import subprocess

def ip_json(*args):
    return json.loads(subprocess.check_output(['ip','-j','-4',*args],timeout=5))

def adapters():
    routes=ip_json('route','show','default')
    result=[]
    for link in ip_json('addr','show','up'):
        for addr in link.get('addr_info',[]):
            if addr.get('scope')!='global':continue
            net=ipaddress.ip_interface(addr['local']+'/'+str(addr['prefixlen']))
            result.append(dict(ip=str(net.ip),name=link['ifname'],network=str(net.network),mask=str(net.netmask),interface_index=link['ifindex'],mac=link.get('address',''),gateways=[r['gateway'] for r in routes if r.get('dev')==link['ifname'] and r.get('gateway')]))
    return sorted(result,key=lambda row:not row['gateways'])

def neighbors():
    try:
        return [dict(ip=r['dst'],interface_index=socket.if_nametoindex(r['dev']),mac=r['lladdr'],source='Linux 邻居表',state='缓存') for r in ip_json('neigh','show') if r.get('lladdr') and not set(r.get('state',[])) & {'FAILED','INCOMPLETE'}],[]
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        return [],[str(exc)]
'''
data['usr/share/lan-inspector/linux_native.py']=native.encode()
data['usr/share/lan-inspector/start.py']=b'import tkinter as tk\nfrom dashboard import Dashboard\nfrom lan_inspector import inspect\nroot=tk.Tk()\napp=Dashboard(root,inspect)\nroot.mainloop()\n'
data['usr/bin/lan-inspector']=b'#!/bin/sh\nexec /usr/bin/python3 /usr/share/lan-inspector/start.py "$@"\n'
data['usr/share/applications/lan-inspector.desktop']='[Desktop Entry]\nType=Application\nName=LAN Inspector\nName[zh_CN]=内网巡检台\nExec=lan-inspector\nTerminal=false\nCategories=Network;\n'.encode()
control=b'Package: lan-inspector\nVersion: 2.4-2\nArchitecture: all\nMaintainer: LAN Inspector <maintainer@localhost>\nDepends: python3 (>= 3.8), python3-tk, iproute2, iputils-ping, iputils-arping, iptables, pkexec\nSection: net\nPriority: optional\nDescription: Offline LAN inventory and interactive desktop topology\n'
exec(Path('work/full_linux24.py').read_text(encoding='utf-8-sig'))
def tar(files):
 buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w:gz',format=tarfile.GNU_FORMAT) as t:
  for k,v in files.items():
   entry=tarfile.TarInfo('./'+k);entry.size=len(v);entry.mode=0o755 if (k.startswith('usr/bin/') or k in ('postinst','prerm')) else 0o644;t.addfile(entry,io.BytesIO(v))
 return buf.getvalue()
out=Path('outputs/lan-inspector_2.4-2_all.deb')
with out.open('wb') as f:
 f.write(b'!<arch>\n')
 for name,v in [('debian-binary',b'2.0\n'),('control.tar.gz',tar(metadata)),('data.tar.gz',tar(data))]:
  f.write(f'{name+"/":16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(v):<10}`\n'.encode()+v+(b'\n' if len(v)%2 else b''))
for k,v in data.items():
 if k.endswith('.py'):compile(v,k,'exec')
with out.open('rb') as f:
 assert f.read(8)==b'!<arch>\n'
 for expected in ('debian-binary','control.tar.gz','data.tar.gz'):
  header=f.read(60);assert header[:16].decode().strip().rstrip('/')==expected
  size=int(header[48:58]);body=f.read(size);f.read(size%2)
  if expected.endswith('.gz'):
   with tarfile.open(fileobj=io.BytesIO(body)) as t:
    for entry in t:assert t.extractfile(entry).read()==(metadata if expected.startswith('control') else data)[entry.name[2:]]
print(out,out.stat().st_size)
