prefix='usr/share/lan-inspector/'
def modify(name,fn):
 data[prefix+name]=fn(data[prefix+name].decode('utf-8-sig')).encode()
data[prefix+'linux_firewall.py']=Path('work/linux_fw24.py').read_bytes()
data[prefix+'linux_ports.py']=Path('work/linux_ports24.py').read_bytes()
data['usr/bin/lan-inspector']=b'#!/bin/sh\nexec /usr/bin/python3 /usr/share/lan-inspector/lan_inspector.py "$@"\n'
change('dashboard.py',"('补充选中 MAC',","('IP 冲突检测',self.open_conflicts),('补充选中 MAC',")
modify('local_ports.py',lambda s:s[:s.index('def is_admin')]+'''def is_admin():
    return os.geteuid()==0

'''+s[s.index('def validate_requests'):s.index('def run_action')]+'from linux_ports import run_action\n\n'+s[s.index('class LocalPortWindow'):])
modify('local_ports.py',lambda s:s[:s.index('        if not is_admin():',s.index('    def mutate'))]+s[s.index('        try:',s.index('    def mutate')):])
modify('local_ports.py',lambda s:'\n'.join(line for line in s.splitlines() if not ("ttk.Button(frame,text='以管理员身份重新打开'" in line)).replace('本机 Windows','本机 Linux').replace('ActiveStore 可见','已验证生效').replace('可扫描，封堵需提权','修改时弹出系统授权'))
modify('conflict_window.py',lambda s:s[:s.index('        if not is_admin():')]+s[s.index('        selected=list',s.index('        if not is_admin():')):])
modify('arp_cache.py',lambda s:s.replace("    if not is_admin():raise PermissionError('清除 ARP 缓存需要管理员权限')","").replace("args=[executable,'interface','ipv4','delete','arpcache','name='+str(index),'store=active']","args=([] if is_admin() else ['/usr/bin/pkexec'])+['/usr/sbin/ip','-4','neigh','flush','dev',next(r['name'] for r in current if r['interface_index']==index)]").replace("args.append('address='+ip)","args.extend(['to',ip+'/32'])").replace('creationflags=0x08000000','creationflags=0'))
change('mac_sources.py','    return ""','''    if not source_ip:return ''
    p=subprocess.run(['arping','-c','1','-w','1','-s',str(source_ip),str(ip)],capture_output=True,timeout=3)
    match=re.search(rb'from '+re.escape(ip.encode())+rb' \\[([0-9A-Fa-f:]{17})\\]',p.stdout)
    return normalize_mac(match.group(1).decode()) if match else '' ''')
modify('mac_sources.py',lambda s:s.replace('指定源网卡 SendARP','指定源地址 arping'))
change('app_paths.py',"    return Path(__import__", "    base=Path(__import__")
change('app_paths.py',"    return Path(sys.executable)", "    base.mkdir(parents=True,exist_ok=True)\n    return base\n    return Path(sys.executable)")
unit='''[Unit]
Description=Restore LAN Inspector inbound port blocks
After=netfilter-persistent.service nftables.service ufw.service
Before=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /usr/share/lan-inspector/linux_firewall.py restore
[Install]
WantedBy=multi-user.target
'''
data['lib/systemd/system/lan-inspector-firewall.service']=unit.encode()
metadata={'control':control,'postinst':b'#!/bin/sh\nset -e\nif command -v systemctl >/dev/null; then systemctl enable lan-inspector-firewall.service; fi\n','prerm':b'#!/bin/sh\nset -e\nif [ "$1" = remove ]; then if [ -f /var/lib/lan-inspector/ports.json ]; then /usr/bin/python3 -I /usr/share/lan-inspector/linux_firewall.py remove < /var/lib/lan-inspector/ports.json; fi; if command -v systemctl >/dev/null; then systemctl disable lan-inspector-firewall.service; fi; fi\n'}
change('local_ports.py',"self.profile_text.set((summary or '未读取到防火墙配置')+'。规则存在不代表已验证网络封堵；防火墙关闭或组织策略禁止本地规则时可能不生效。')","self.profile_text.set('规则表显示本工具保存的封堵配置。普通用户可能只能看到自己进程的名称和 PID。')")
change('linux_ports.py',"text=subprocess.check_output(['ss'", "text=subprocess.check_output((['/usr/bin/pkexec'] if action=='scan-admin' and os.geteuid() else [])+['/usr/bin/ss'")
change('local_ports.py',"('勾选全部监听端口',","('授权查看所有进程',lambda:self.submit('scan-admin')),('勾选全部监听端口',")
change('local_ports.py',"{'scan':'读取本机端口和规则',","{'scan-admin':'读取所有进程和端口','scan':'读取本机端口和规则',")
modify('linux_ports.py',lambda s:s.replace("'/usr/bin/ss'","'/usr/bin/ss' if Path('/usr/bin/ss').exists() else '/usr/sbin/ss'"))
