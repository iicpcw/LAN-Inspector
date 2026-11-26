"""Windows adapter discovery and bounded ICMP latency sampling."""
import ipaddress
import json
import locale
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time


def local_networks():
    script = r"""
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference='Stop'
$out=@()
foreach($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if($nic.OperationalStatus -ne 'Up') { continue }
    $p=$nic.GetIPProperties()
    foreach($u in $p.UnicastAddresses) {
        if($u.Address.AddressFamily -eq 'InterNetwork' -and -not [Net.IPAddress]::IsLoopback($u.Address)) {
            $out += [pscustomobject]@{
                ip=$u.Address.ToString()
                mask=$u.IPv4Mask.ToString()
                name=$nic.Name
                mac=$nic.GetPhysicalAddress().ToString()
                interface_index=$p.GetIPv4Properties().Index
                gateways=@($p.GatewayAddresses | ForEach-Object {$_.Address.ToString()} | Where-Object { $_ -match '^[0-9]+\.' -and $_ -ne '0.0.0.0' })
            }
        }
    }
}
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
"""
    exe=str(Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe')
    p=subprocess.run([exe,'-NoProfile','-NonInteractive','-Command',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,creationflags=0x08000000)
    if p.returncode:raise RuntimeError('本机网卡查询失败，请手动填写完整网段')
    raw=json.loads(p.stdout.decode('utf-8-sig'))
    result=[]
    for item in raw:
        net=ipaddress.ip_network(item['ip']+'/'+item['mask'],strict=False)
        if not ipaddress.ip_address(item['ip']).is_link_local:
            result.append(dict(item,network=str(net)))
    result.sort(key=lambda r:not bool(r.get('gateways')))
    return result


def reverse_name(ip):
    try:
        p=subprocess.run(['nslookup','-timeout=1','-retry=1',ip],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2,creationflags=0x08000000)
        text=p.stdout.decode(locale.getpreferredencoding(False),'replace')
        match=re.search(r'(?im)^\s*(?:Name|名称|名字)\s*[:：]\s*(\S+)',text)
        return match.group(1).rstrip('.')[:253] if match else ''
    except (OSError,subprocess.TimeoutExpired):return ''


def latency(ip, stop=None, count=4):
    ip=str(ipaddress.IPv4Address(ip))
    samples=[]
    errors=[]
    for _ in range(count):
        if stop and stop.is_set():break
        try:
            p=subprocess.run(['ping','-n','1','-w','1000',ip],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2,creationflags=0x08000000)
            found=None
            target=re.compile(rb'(?<![0-9.])'+re.escape(ip.encode())+rb'(?![0-9.])')
            for line in p.stdout.splitlines():
                if p.returncode==0 and target.search(line) and re.search(rb'\bTTL[= ]+\d+',line,re.I):
                    m=re.search(rb'([=<])\s*(\d+)\s*ms',line,re.I)
                    if m:found=0.5 if m.group(1)==b'<' and int(m.group(2))==1 else float(m.group(2))
            samples.append(found)
        except (OSError,subprocess.TimeoutExpired) as exc:
            samples.append(None);errors.append(str(exc))
        if stop:stop.wait(.2)
        else:time.sleep(.2)
    received=[x for x in samples if x is not None]
    return dict(ip=ip,sent=len(samples),received=len(received),loss=round((len(samples)-len(received))*100/max(1,len(samples)),1),
                minimum=min(received) if received else None,maximum=max(received) if received else None,
                average=round(sum(received)/len(received),2) if received else None,samples=samples,errors=errors,
                note='ICMP 往返时延；<1ms 按 0.5ms 统计；无响应可能为 ICMP 被过滤，不能据此认定离线')
