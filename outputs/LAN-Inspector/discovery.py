"""Bounded service identification and offline logical topology rendering."""
import datetime
import html
import ipaddress
from pathlib import Path
import re
import socket
import ssl
import time
from fingerprint_engine import analyze
from device_icons import icon_kind, svg_icon


def read_banner(ip, port, timeout):
    """One bounded SSH/HTTP request. No login, redirects or remote resource loads."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            if port in (443, 8443, 5986):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(raw, server_hostname=ip) as conn:
                    return http_read(conn, ip)
            if port in (80, 8080, 8000, 5985):
                return http_read(raw, ip)
            if port == 22:
                data=b'';deadline=time.monotonic()+1.5
                while len(data)<4096 and time.monotonic()<deadline:
                    raw.settimeout(max(.05,min(.5,deadline-time.monotonic())))
                    try:part=raw.recv(4096-len(data))
                    except socket.timeout:continue
                    if not part:break
                    data+=part
                    if re.search(rb'(?m)^SSH-[^\r\n]+[\r\n]',data):break
                return data.decode('utf-8','replace')
    except (OSError, ssl.SSLError):
        pass
    return ''


def http_read(conn, ip):
    conn.sendall(('GET / HTTP/1.0\r\nHost: ' + ip + '\r\nConnection: close\r\n\r\n').encode('ascii'))
    # Read split header/title packets, with an absolute budget and size limit.
    deadline=time.monotonic()+2.0
    chunks=[];size=0
    while size<32768 and time.monotonic()<deadline:
        conn.settimeout(max(.05,min(.5,deadline-time.monotonic())))
        try:part=conn.recv(min(4096,32768-size))
        except socket.timeout:continue
        if not part:break
        chunks.append(part);size+=len(part)
        joined=b''.join(chunks)
        if b'</title>' in joined.lower():break
        if b'\r\n\r\n' in joined:
            head,body=joined.split(b'\r\n\r\n',1)
            length=re.search(rb'(?im)^Content-Length:\s*(\d+)',head)
            if length and len(body)>=int(length.group(1)):break
    return b''.join(chunks).decode('utf-8','replace')


def classify(opened, banners):
    result=analyze(opened,banners)
    return result['device_type'],result['confidence'],result['fingerprint']


def identify(ip, opened, timeout, stop):
    banners = {}
    for port in opened:
        if stop.is_set():
            break
        if port in (22, 80, 443, 8000, 8080, 8443, 5985, 5986):
            value = read_banner(ip, port, timeout)
            if value:
                # Keep readable evidence without terminal control characters.
                banners[str(port)] = ''.join(c for c in value if c in '\n\t' or ord(c) >= 32)[:32768]
    result=analyze(opened,banners)
    result['service_banners']='\n'.join('TCP '+p+': '+v for p,v in banners.items())
    return result


def topology_html(rows, target_text):
    nets = [ipaddress.ip_network(x, strict=False) for x in target_text.replace(',', ' ').split()]
    nets = sorted(set(nets), key=lambda n: (-n.prefixlen, int(n.network_address)))
    groups = {str(n): [] for n in nets}
    unseen = 0
    for row in rows:
        if row['status'] == '未确认':
            unseen += 1
            continue
        net = next((str(n) for n in nets if ipaddress.ip_address(row['ip']) in n), '其他')
        groups.setdefault(net, []).append(row)
    esc = lambda value: html.escape(str(value), quote=True)
    sections = []
    for net, hosts in groups.items():
        if not hosts:
            continue
        hosts = sorted(hosts, key=lambda r: ipaddress.ip_address(r['ip']))
        width, height = 1120, 105 + ((len(hosts)+3)//4)*180
        parts = ['<svg role="img" aria-label="网段逻辑归属图" viewBox="0 0 %d %d">' % (width,height)]
        parts.append('<rect x="390" y="12" width="340" height="46" rx="12" fill="#243b64"/><text x="560" y="41" text-anchor="middle" fill="white">%s · 逻辑网段</text>' % esc(net))
        for i, row in enumerate(hosts):
            x, y = 15+(i%4)*278, 100+(i//4)*180
            color = '#b42318' if row.get('risk_ports') else ('#238571' if row['status']=='在线' else '#aa7629')
            parts.append('<path d="M560 58 L560 75 L%d 75 L%d %d" fill="none" stroke="#879bb9" stroke-dasharray="5 6"/>' % (x+130,x+130,y))
            title = '\n'.join(str(row.get(k,'')) for k in ('ip','status','mac','device_type','confidence','fingerprint','warning','audit_status','audit_detail','mac_vendor','mac_scope','vendor_prefix','vendor_evidence','device_hint'))
            parts.append('<g><title>%s</title><ellipse cx="%d" cy="%d" rx="56" ry="52" fill="white" stroke="%s" stroke-width="2"/>' % (esc(title),x+130,y+55,color))
            kind=icon_kind(row.get('device_type','未知设备'))
            parts.append(svg_icon(kind,x+94,y+18,color))
            detail_id='device-'+re.sub('[^a-zA-Z0-9-]','-',str(row['ip']))
            lines=[row.get('hostname') or row['ip'],row['ip']]
            for j,line in enumerate(lines):
                parts.append('<text x="%d" y="%d" text-anchor="middle" fill="#243b64" font-size="13">%s</text>' % (x+130,y+131+j*22,esc(line[:29]+('…' if len(line)>29 else ''))))
            # Only an IP-derived safe identifier enters the fixed event handler.
            parts.append('<a href="#%s" onclick="document.getElementById(&quot;%s&quot;).open=true"><rect x="%d" y="%d" width="260" height="158" fill="transparent" style="cursor:pointer"/></a>' % (detail_id,detail_id,x,y))
            parts.append('</g>')
        parts.append('</svg>')
        sections.append(''.join(parts))
    fields=[('IP','ip'),('状态','status'),('设备类别','device_type'),('服务标识厂商','device_vendor'),('厂商置信度','vendor_confidence'),('产品线索','model_hint'),('软件平台线索','platform_hint'),('OS','os_family'),('OS 置信度','os_confidence'),('MAC','mac'),('MAC 来源','mac_source'),('MAC 网卡','mac_interface'),('MAC 状态','mac_state'),('MAC 说明','mac_note'),('MAC 候选','mac_candidates'),('开放端口','ports'),('置信度','confidence'),('识别依据','fingerprint'),('提示','warning'),('封堵检查','audit_status'),('未封堵端口','risk_ports'),('检查详情','audit_detail'),('本次规则','policy_ports'),('未完成检查端口','unchecked_policy_ports'),('MAC 注册厂商','mac_vendor'),('MAC 属性','mac_scope'),('匹配前缀','vendor_prefix'),('厂商依据','vendor_evidence'),('设备推测与限制','device_hint')]
    details=''.join('<details id="device-'+re.sub('[^a-zA-Z0-9-]','-',str(r['ip']))+'"><summary>'+esc(r.get('hostname') or r['ip'])+' · '+esc(r['status'])+' · 查看详情</summary><table>'+''.join('<tr><th>'+label+'</th><td>'+esc(r.get(key,''))+'</td></tr>' for label,key in fields)+'</table></details>' for r in rows)
    return '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>内网逻辑拓扑</title>
<style>body{font:14px system-ui;background:#edf2f8;color:#243b64;margin:32px}main{max-width:1400px;margin:auto}svg{width:100%;min-width:850px;background:#f7f9fd;border-radius:14px;margin:12px 0}section{overflow:auto}table{border-collapse:collapse;width:100%;background:white}td,th{border:1px solid #d4deeb;padding:10px;text-align:left;overflow-wrap:anywhere}p{line-height:1.8}details{margin:12px 0;background:white;padding:14px;border-radius:8px}summary{cursor:pointer;font-weight:600}details:target{outline:2px solid #1565c0}.note{padding:16px;background:#fff3d4;border-radius:10px}@media print{body{margin:8px}svg{min-width:0}tr{break-inside:avoid}}</style>
<main><h1>内网逻辑拓扑 · 扫描视图</h1><p>生成时间：''' + esc(datetime.datetime.now().isoformat(timespec='seconds')) + '''</p><p class="note">虚线仅表示扫描目标中的网段归属，不表示物理连线、交换机端口、下一跳或实际路由。当前扫描没有 LLDP/CDP、交换机转发表或路由表证据。设备类型为服务指纹推测，不能保证正确。MAC 厂商是地址段注册组织，不等于整机品牌；随机/本地 MAC 不推断厂商，无法仅凭 MAC 区分 iOS、Android。红色为命中本次封堵规则的设备（常见高危端口未封堵），绿色为探测在线，棕色为仅 ARP 响应（不计在线）。未确认地址仅列于下表。</p><p>目标：''' + esc(target_text) + '；未确认：' + str(unseen) + '；结果记录：' + str(len(rows)) + '；未封堵告警设备：' + str(sum(bool(r.get('risk_ports')) for r in rows)) + '</p><section>' + ''.join(sections) + '</section><h2>设备详情（点击图标或展开下列设备）</h2>' + details + '</main></html>'


def save_topology(rows, target_text, directory):
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    name = 'topology-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.html'
    path = folder / name
    path.write_text(topology_html(rows, target_text), encoding='utf-8')
    return path
