"""Separate hardware-role and OS evidence; HTTP body prose is not an OS fingerprint."""
import html
import re
from enterprise_fingerprints import match_enterprise


def service_facts(banners):
    facts=[]
    for port,value in banners.items():
        value=str(value)
        if value.lstrip().upper().startswith('HTTP/'):
            head,_,body=value.partition('\r\n\r\n')
            if not body and '\n\n' in value:head,body=value.split('\n\n',1)
            for name in ('Server','WWW-Authenticate'):
                for match in re.finditer(r'(?im)^'+name+r':\s*([^\r\n]+)',head):
                    facts.append(dict(port=str(port),source='HTTP '+name,text=match.group(1)[:512]))
            match=re.search(r'<title\b[^>]*>(.*?)</title>',body,re.I|re.S)
            if match:facts.append(dict(port=str(port),source='HTTP title',text=html.unescape(re.sub('<[^>]+>',' ',match.group(1)))[:512]))
        else:
            for line in value.splitlines()[:8]:
                if line.startswith('SSH-'):
                    facts.append(dict(port=str(port),source='SSH identification',text=line[:512]));break
            else:
                # Legacy/imported non-HTTP service identification; never the HTTP page body.
                facts.append(dict(port=str(port),source='service banner',text=value[:512]))
    return facts


def analyze(opened,banners):
    facts=service_facts(banners)
    devices=[];systems=[];evidence=[]
    device_rules=[
        ('防火墙',r'fortigate|fortios|palo alto|pan-os|sophos firewall|sonicwall|pfsense|opnsense|cisco asa|cisco adaptive security'),
        ('交换机',r'catalyst|procurve|arubaos-switch|huawei.*s[23567]\d{3}|h3c.*s[23567]\d{3}|cisco.*sg[235]\d{2}|交换机管理'),
        ('路由器',r'routeros|mikrotik|openwrt|vyos|edgeos|miwifi|小米路由器|红米路由器|asus.*router|tp-link.*(?:router|路由)|(?:wireless|wi-fi|wifi) router|华硕路由器|腾达路由器'),
        ('NAS 设备',r'synology.*diskstation|diskstation manager|qnap.*(?:nas|turbo)|truenas'),
        ('打印设备/打印服务',r'laserjet|officejet|jetdirect|epson.*printer|brother.*printer'),
    ]
    os_rules=[('Windows',r'microsoft-iis|microsoft-httpapi|openssh_for_windows'),('Linux',r'ubuntu|debian|centos|rocky linux|almalinux|fedora|\blinux\b'),('macOS',r'\bdarwin\b|\bmacos\b')]
    for fact in facts:
        text=fact['text'];low=text.lower()
        if fact['source']=='HTTP title' and re.search(r'下载|教程|文档|support|manual|guide|download|documentation|tutorial|\bdocs?\b',low):continue
        for label,pattern in device_rules:
            match=re.search(pattern,low)
            if match:
                devices.append(label);evidence.append(dict(dimension='device',candidate=label,match=match.group(0),**fact))
        # A page title says what the page is about, not which OS is running.
        if fact['source'] in ('SSH identification','HTTP Server','service banner'):
            for label,pattern in os_rules:
                match=re.search(pattern,low)
                if match:systems.append(label);evidence.append(dict(dimension='os',candidate=label,match=match.group(0),**fact))
            for marker,label in [('openwrt','Linux'),('routeros','RouterOS'),('fortios','FortiOS'),('pan-os','PAN-OS'),('pfsense','FreeBSD'),('opnsense','FreeBSD')]:
                if marker in low:systems.append(label);evidence.append(dict(dimension='os',candidate=label,match=marker,**fact))
        if fact['source'] in ('SSH identification','HTTP Server','service banner') and not re.search(r'support|download|兼容|下载|支持',low):
            if re.search(r'iphone os|ipad; cpu os|apple mobile device',low):
                devices.append('疑似 iOS/iPadOS 移动设备');systems.append('iOS/iPadOS');evidence.append(dict(dimension='os',candidate='iOS/iPadOS',match=text,**fact))
            if re.search(r'\bandroid(?:[ /;]|$)',low):
                devices.append('疑似 Android 设备');systems.append('Android');evidence.append(dict(dimension='os',candidate='Android',match=text,**fact))
    enterprise=match_enterprise(facts)
    devices.extend(enterprise['devices']);systems.extend(enterprise['systems']);evidence.extend(enterprise['evidence'])
    devices=list(dict.fromkeys(devices));systems=list(dict.fromkeys(systems))
    if 'Android' in systems and 'Linux' in systems:systems.remove('Linux')
    if len(devices)>1:kind='类型待核实';confidence='低'
    elif devices:kind=devices[0];confidence='低' if kind.startswith('疑似') else '中'
    elif len(systems)==1 and systems[0] in ('VRP','Comware'):kind='网络设备（具体类型未知）';confidence='低'
    elif systems==['Windows']:kind='Windows 终端/服务器';confidence='中'
    elif systems==['Linux']:kind='Linux 终端/服务器';confidence='中'
    elif systems==['macOS']:kind='macOS 终端';confidence='中'
    elif len(systems)>1:kind='类型待核实';confidence='低'
    elif 445 in opened and (135 in opened or 3389 in opened):kind='疑似 Windows 终端/服务器';confidence='低'
    elif 22 in opened:kind='SSH 设备（类型未知）';confidence='低'
    else:kind='未知设备';confidence='未知'
    os_name=' / '.join(systems) if len(systems)<=1 else '待核实：'+' / '.join(systems)
    os_confidence='低' if len(systems)>1 or any(v in systems for v in ('Android','iOS/iPadOS')) else ('中' if systems else '未知')
    if not systems and kind.startswith('疑似 Windows'):
        os_name='疑似 Windows（端口线索）';os_confidence='低'
    if not os_name:os_name='未知'
    reasons=['TCP '+f['port']+' '+f['source']+' → '+f['candidate']+' ['+f['match']+']' for f in evidence]
    if not reasons:
        reasons=['仅有端口线索，不能确定硬件类型或 OS；SSH/HTTP/SMB 等服务也可跨系统运行']
    reasons.append('服务可能来自代理、容器或自定义内容；未验证具体硬件型号/OS 版本')
    return dict(device_vendor=' / '.join(enterprise['vendors']) or '未知',vendor_confidence='中' if len(enterprise['vendors'])==1 else ('低' if enterprise['vendors'] else '未知'),vendor_candidates=enterprise['vendors'],model_hint='；'.join(enterprise['models']) or '未知',platform_hint=' / '.join(enterprise['platforms']) or '未知',device_type=kind,confidence=confidence,os_family=os_name,os_confidence=os_confidence,
                fingerprint='；'.join(reasons),identification_evidence=evidence,
                device_candidates=devices,os_candidates=systems,service_facts=facts)
