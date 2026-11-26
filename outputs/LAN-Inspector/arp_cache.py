"""Explicit, interface-scoped clearing of the active Windows ARP cache."""
import ipaddress
import locale
import os
from pathlib import Path
import subprocess
import sys
import ctypes
from local_ports import is_admin
from app_paths import app_dir, launch_args
from network_tools import local_networks


def clear_cache(adapter,targets=(),all_on_interface=False):
    if not is_admin():raise PermissionError('清除 ARP 缓存需要管理员权限')
    index=adapter.get('interface_index')
    if isinstance(index,bool) or not isinstance(index,int) or index<=0:raise ValueError('网卡索引不可用，请重新识别网卡')
    current=local_networks()
    if not any(r.get('interface_index')==index and r['ip']==adapter['ip'] for r in current):raise ValueError('网卡配置已变化，请重新识别后再操作')
    addresses=sorted({str(ipaddress.IPv4Address(ip)) for ip in targets})
    if not all_on_interface and not addresses:raise ValueError('请先选中要清理的 IP；不会自动扩大到整张网卡')
    net=ipaddress.ip_network(adapter['network'])
    if any(ipaddress.ip_address(ip) not in net for ip in addresses):raise ValueError('目标 IP 不属于所选网卡直连网段')
    if all_on_interface and addresses:raise ValueError('清理范围不明确')
    executable=str(Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/netsh.exe')
    results=[]
    for ip in ([None] if all_on_interface else addresses):
        args=[executable,'interface','ipv4','delete','arpcache','name='+str(index),'store=active']
        if ip:args.append('address='+ip)
        try:
            process=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20,creationflags=0x08000000)
            message=process.stdout.decode(locale.getpreferredencoding(False),'replace').strip()
            results.append(dict(ip=ip or '所选网卡全部活动缓存',interface_index=index,success=process.returncode==0,message=message or '命令已返回'))
        except subprocess.TimeoutExpired:
            results.append(dict(ip=ip or '所选网卡全部活动缓存',interface_index=index,success=False,message='操作超时，结果未确认；请重新读取缓存核实'))
    return results


def elevate_topology(asset_file):
    base=Path(__file__).resolve().parent
    args=subprocess.list2cmdline(launch_args('--topology','--inventory',str(Path(asset_file).resolve()),'--no-auto-scan'))
    result=ctypes.windll.shell32.ShellExecuteW(None,'runas',sys.executable,args,str(app_dir()),1)
    if result<=32:raise RuntimeError('未能以管理员启动，可能取消了 UAC 授权')
