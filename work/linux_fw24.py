import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

STATE=Path('/var/lib/lan-inspector')
def rule(tool,op,proto,port):
    args=[tool,'-w','5',op,'INPUT']
    if op=='-I':args.append('1')
    args += ['-p',proto,'--dport',str(port),'-m','comment','--comment','LANInspector.v1.'+proto+'.'+str(port),'-j','DROP']
    r=subprocess.run(args,capture_output=True,text=True)
    if r.returncode and (op!='-C' or r.returncode!=1):raise RuntimeError(r.stderr.strip() or '防火墙操作失败')
    return r.returncode==0

def main():
    action=sys.argv[1]
    if action not in ('block','remove','restore'):raise ValueError('invalid action')
    STATE.mkdir(mode=0o755,exist_ok=True)
    with (STATE/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        path=STATE/'ports.json'
        saved=json.loads(path.read_text()) if path.exists() else []
        items=saved if action=='restore' else json.loads(sys.stdin.read(131072))
        for item in items:
            proto=item['protocol'].lower()
            port=item['port']
            if proto not in ('tcp','udp') or type(port)!=int or not 1<=port<=65535:raise ValueError('invalid port')
            row=dict(protocol=proto.upper(),port=port)
            # Persist intent first so an interrupted dual-stack update can be retried.
            if row not in saved and action=='block':
                saved.append(row)
                write(path,saved)
            for tool in ['/usr/sbin/iptables']+(['/usr/sbin/ip6tables'] if Path('/proc/net/if_inet6').exists() else []):
                present=rule(tool,'-C',proto,port)
                if action=='remove' and present:rule(tool,'-D',proto,port)
                if action!='remove' and not present:rule(tool,'-I',proto,port)
            if action=='remove' and row in saved:
                saved.remove(row)
                write(path,saved)
def write(path,rows):
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(rows))
    tmp.chmod(0o644)
    tmp.replace(path)
if __name__=='__main__':main()
