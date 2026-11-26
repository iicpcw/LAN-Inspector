"""Interface-scoped, provenance-labelled Windows MAC acquisition."""
import base64
import ctypes
import datetime
import ipaddress
import json
import locale
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time
from ip_conflict import normalize_mac
from network_tools import local_networks
from mac_identity import lookup


def active_arp(ip,source_ip=None):
    try:
        destination=ctypes.c_ulong(int.from_bytes(socket.inet_aton(ip),'little'))
        source=ctypes.c_ulong(int.from_bytes(socket.inet_aton(source_ip),'little')) if source_ip else 0
        buf=(ctypes.c_ubyte*6)();size=ctypes.c_ulong(6)
        code=ctypes.windll.iphlpapi.SendARP(destination,source,ctypes.byref(buf),ctypes.byref(size))
        return normalize_mac(':'.join('%02X'%b for b in buf)) if code==0 and size.value==6 else ''
    except (OSError,AttributeError):return ''


def parse_arp(text):
    rows=[];index=None;source=None
    for line in text.splitlines():
        header=re.search(r'(\d+\.\d+\.\d+\.\d+)\s+---\s+(0x[0-9a-fA-F]+)',line)
        if header:
            source=header.group(1);index=int(header.group(2),16);continue
        match=re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})\s+(.+?)\s*$',line)
        if match and index is not None:
            mac=normalize_mac(match.group(2))
            if mac:rows.append(dict(ip=match.group(1),mac=mac,interface_index=index,source_ip=source,state=match.group(3),source='arp -a 缓存'))
    return rows


def cache_snapshot():
    rows=[];errors=[]
    system=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32'
    script="""[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);$ErrorActionPreference='Stop';try {$r=@(Get-NetNeighbor -AddressFamily IPv4 | ForEach-Object {[pscustomobject]@{ip=$_.IPAddress;mac=$_.LinkLayerAddress;interface_index=[int]$_.InterfaceIndex;state=[string]$_.State}});ConvertTo-Json -InputObject @{rows=$r} -Depth 5 -Compress} catch {ConvertTo-Json -InputObject @{rows=@();error=$_.Exception.Message} -Compress}"""
    try:
        encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
        p=subprocess.run([str(system/'WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile','-NonInteractive','-EncodedCommand',encoded],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,creationflags=0x08000000)
        data=json.loads(p.stdout.decode('utf-8-sig'))
        if data.get('error'):errors.append('邻居表：'+data['error'])
        for item in data.get('rows',[]):
            mac=normalize_mac(item.get('mac',''))
            if mac and item.get('state') in ('Reachable','Stale','Delay','Probe','Permanent'):
                rows.append(dict(item,mac=mac,source='Windows 邻居表'))
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as exc:errors.append('邻居表不可用：'+str(exc))
    try:
        p=subprocess.run([str(system/'arp.exe'),'-a'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,creationflags=0x08000000)
        if p.returncode==0:rows.extend(parse_arp(p.stdout.decode(locale.getpreferredencoding(False),'replace')))
        else:errors.append('arp -a 未成功返回')
    except (OSError,subprocess.TimeoutExpired) as exc:errors.append('arp -a 不可用：'+str(exc))
    return rows,errors


def skip_name(data,offset):
    while True:
        if offset>=len(data):raise ValueError('truncated name')
        size=data[offset];offset+=1
        if size==0:return offset
        if size&0xC0==0xC0:
            if offset>=len(data):raise ValueError('truncated pointer')
            return offset+1
        if size>63 or offset+size>len(data):raise ValueError('invalid name')
        offset+=size


def parse_nbstat(data,transaction):
    try:
        if len(data)<12:return ''
        tid,flags,questions,answers,_,_=struct.unpack('!6H',data[:12])
        if tid!=transaction or not flags&0x8000 or flags&0x7A0F or questions>2 or answers>16:return ''
        offset=12
        for _ in range(questions):offset=skip_name(data,offset)+4
        for _ in range(answers):
            offset=skip_name(data,offset)
            if offset+10>len(data):return ''
            rrtype,rrclass,ttl,length=struct.unpack('!HHIH',data[offset:offset+10]);offset+=10
            payload=data[offset:offset+length];offset+=length
            if len(payload)!=length:return ''
            if rrtype==0x21 and rrclass==1 and payload:
                start=1+18*payload[0]
                if len(payload)>=start+6:return normalize_mac(':'.join('%02X'%b for b in payload[start:start+6]))
    except (ValueError,struct.error):return ''
    return ''


def netbios_mac(ip,source_ip):
    transaction=struct.unpack('!H',os.urandom(2))[0]
    name=b'*'+b'\0'*15
    encoded=bytes(c for byte in name for c in (65+(byte>>4),65+(byte&15)))
    query=struct.pack('!6H',transaction,0,1,0,0,0)+b'\x20'+encoded+b'\0'+struct.pack('!HH',0x21,1)
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(.7);sock.bind((source_ip,0));sock.sendto(query,(ip,137))
            data,peer=sock.recvfrom(8192)
            if peer[0]!=ip or peer[1]!=137:return ''
            return parse_nbstat(data,transaction)
    except OSError:return ''


class MacContext:
    def __init__(self,adapters=None,preferred_source=None):
        self.errors=[]
        if adapters is None:
            try:adapters=local_networks()
            except Exception as exc:adapters=[];self.errors.append('本机网卡不可用：'+str(exc))
        self.adapters=list(adapters);self.preferred_source=preferred_source;self.cache=[]

    def refresh(self):
        self.cache,errors=cache_snapshot();self.errors.extend(errors);self.errors=self.errors[-8:]

    def adapter(self,ip):
        address=ipaddress.IPv4Address(ip)
        own=next((a for a in self.adapters if a['ip']==ip),None)
        if own:return own,''
        if self.preferred_source and not any(a['ip']==self.preferred_source for a in self.adapters):return None,'源网卡 IP 已变化，请重新识别并选择网卡'
        candidates=[a for a in self.adapters if address in ipaddress.ip_network(a['network'])]
        preferred=next((a for a in candidates if a['ip']==self.preferred_source),None)
        if preferred:return preferred,''
        if not candidates:return None,'非已确认直连网段，不能通过本机 ARP 获取终端 MAC'
        length=max(ipaddress.ip_network(a['network']).prefixlen for a in candidates)
        candidates=[a for a in candidates if ipaddress.ip_network(a['network']).prefixlen==length]
        if len(candidates)!=1:return None,'多张网卡覆盖同一目标，请在拓扑网卡列表明确选择源网卡'
        return candidates[0],''

    def resolve(self,ip,stop,active=True,retry=False,netbios=False):
        result=dict(mac='',mac_source='',mac_interface='',mac_state='未获取',mac_confidence='未知',mac_candidates=[],mac_errors=list(self.errors),mac_note='',mac_checked_at=datetime.datetime.now().isoformat(timespec='seconds'))
        adapter,note=self.adapter(ip)
        if not adapter:result['mac_note']=note;return result
        result['mac_interface']=adapter['name']+' | '+adapter['ip']+' | ifIndex='+str(adapter.get('interface_index','未知'))
        if stop.is_set():result['mac_note']='已取消';return result
        candidates=[]
        def record(value,source,state):
            value=normalize_mac(value)
            if value:candidates.append(dict(mac=value,source=source,state=state))
        if ip==adapter['ip']:record(adapter.get('mac',''),'本机网卡配置','本机读取')
        elif active:
            for attempt in range(2 if retry else 1):
                try:record(active_arp(ip,adapter['ip']),'指定源网卡 SendARP','主动 ARP / 系统解析')
                except Exception as exc:result['mac_errors'].append(str(exc))
                if candidates or stop.is_set():break
                if attempt==0 and retry:stop.wait(.1)
        for row in self.cache:
            if row['ip']!=ip or row.get('interface_index')!=adapter.get('interface_index'):continue
            if row.get('source_ip') and row['source_ip']!=adapter['ip']:
                if not any(a['ip']==row['source_ip'] and a.get('interface_index')==adapter.get('interface_index') for a in self.adapters):continue
            record(row['mac'],row['source'],row.get('state','缓存'))
        if not candidates and netbios and not stop.is_set():
            value=netbios_mac(ip,adapter['ip']);record(value,'NetBIOS NBSTAT UDP/137','设备自报 UNIT_ID，未验证链路归属')
        result['mac_candidates']=candidates
        strong=[r for r in candidates if r['source'] in ('本机网卡配置','指定源网卡 SendARP')]
        values={r['mac'] for r in candidates}
        if len(values)>1:
            result['mac_note']='不同来源存在不同 MAC，可能为缓存过期/地址变化/代理；不能直接判定 IP 冲突'
            if not strong:result['mac_state']='来源不一致，待核实';return result
        if candidates:
            chosen=strong[0] if strong else candidates[0]
            result.update(mac=chosen['mac'],mac_source=chosen['source'],mac_state=chosen['state'],mac_confidence='高（本机读取）' if chosen['source']=='本机网卡配置' else ('中（需核实代理）' if strong else '低（缓存或设备自报）'))
            if not result['mac_note']:result['mac_note']='缓存记录可能过期；设备自报不一定代表当前网口；均不单独证明在线' if not strong else 'ARP 仍可能由代理设备响应，不能作为身份认证'
        return result

    def enrich(self,row,stop,active=True,netbios=False):
        result=self.resolve(row['ip'],stop,active=active,retry=row.get('status')=='在线',netbios=netbios)
        row=dict(row);row.update(result);row.update(lookup(result['mac']))
        if row['status'] in ('未确认','仅 ARP 响应','仅缓存记录','仅设备自报 MAC') and result['mac']:
            row['status']='仅 ARP 响应' if result['mac_source']=='指定源网卡 SendARP' else ('仅设备自报 MAC' if result['mac_source'].startswith('NetBIOS') else ('在线' if result['mac_source']=='本机网卡配置' else '仅缓存记录'))
        return row
