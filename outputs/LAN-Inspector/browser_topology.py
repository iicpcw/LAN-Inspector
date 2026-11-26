import json
import webbrowser
import tempfile
from pathlib import Path
from device_icons import icon_kind

PAGE = """<!doctype html><meta charset=utf-8><title>动态资产拓扑</title>
<style>*{box-sizing:border-box}body{font:16px system-ui;background:#edf2f8;color:#20354d;margin:24px}header{position:sticky;top:0;background:#edf2f8;padding:12px 0}input,button{font:inherit;padding:8px}section{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:12px}button{background:white;color:#20354d;border:1px solid #cad5df;border-radius:10px;overflow-wrap:anywhere;cursor:pointer}dialog{max-width:min(650px,94vw)}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>
<header><strong>动态资产拓扑</strong>　<input id=q placeholder="搜索名称、IP、类别"></header><main id=m></main><dialog id=d><button onclick="d.close()">关闭详情</button><pre id=p></pre></dialog>
<script>
let previous='',data=[];
function render(){m.replaceChildren();for(const [net,rows] of data){let h=document.createElement('h3'),g=document.createElement('section');h.textContent=net;m.append(h,g);for(const r of rows){if(!Object.values(r).join(' ').toLowerCase().includes(q.value.toLowerCase()))continue;let b=document.createElement('button');b.textContent=r['图标']+' '+r['名称']+' · '+r.IP+' · '+r['状态'];b.onclick=()=>{p.textContent=Object.entries(r).filter(([k])=>k!=='图标').map(([k,v])=>k+'：'+v).join('\\n');d.showModal()};g.append(b)}}if(!data.length)m.textContent='当前拓扑为空'}
window.updateTopology=v=>{let key=JSON.stringify(v);if(key!==previous){previous=key;data=v;render()}};q.oninput=render;
function load(){let s=document.createElement('script');s.src='assets.js?t='+Date.now();s.onload=s.onerror=()=>s.remove();document.head.append(s)}load();setInterval(load,2000)
</script>"""

class BrowserTopology:
    def __init__(self):
        self.folder = Path(tempfile.mkdtemp(prefix='lan-topology-'))
        (self.folder/'index.html').write_text(PAGE, encoding='utf-8')
        self.last = None

    def update(self, dashboard):
        icons = dict(computer='🖥️', phone='📱', tablet='📱', router='📡', switch='🔀', firewall='🛡️', server='🗄️', printer='🖨️')
        groups = []
        networks = dashboard.visible_networks()
        for network in networks:
            rows = []
            for asset in dashboard.model.assets.values():
                if dashboard.visible_group(asset, network, networks):
                    item = dashboard.model.displayed(asset)
                    rows.append({'图标':icons.get(icon_kind(item['category']), '◇'),'名称':item['name'],'IP':asset['ip'],'MAC':item['mac'],'类别':item['category'],'系统':item['os_family'],'状态':item['status'],'备注':asset['note']})
            groups.append((network, rows))
        content = 'window.updateTopology('+json.dumps(groups,ensure_ascii=True)+');'
        if content != self.last:
            temp = self.folder/'assets.tmp'
            temp.write_text(content,encoding='utf-8')
            temp.replace(self.folder/'assets.js')
            self.last = content

    def open(self):
        webbrowser.open((self.folder/'index.html').as_uri())
