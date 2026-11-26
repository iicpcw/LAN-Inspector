"""Conservative enterprise product families; vendor alone never selects a role."""
import re

VENDORS=[('华为',r'huawei|华为|cloudengine|hisecengine|netengine'),('华三 H3C',r'\bh3c|华三|新华三'),('中兴 ZTE',r'\bzte|中兴|zxr10|\bzxhn\b'),('深信服',r'sangfor|深信服|\bngaf\b|\batrust\b|easyconnect')]
RULES=[
    ('华为','路由器',r'\bar\d{3,5}[a-z0-9-]*\b|\bne(?:40|80|5000|9000)[a-z0-9-]*\b|netengine\s+(?:ar\s*)?\d{3,5}[a-z0-9-]*|华为[^\r\n]{0,40}路由器'),
    ('华为','交换机',r'\bs\d{4,5}[a-z0-9-]*\b|\bce\d{4,5}[a-z0-9-]*\b|cloudengine[^\r\n]{0,30}switch|华为[^\r\n]{0,40}交换机'),
    ('华为','防火墙',r'\busg\s*-?\d{3,5}[a-z0-9-]*\b|华为[^\r\n]{0,40}防火墙'),
    ('华三 H3C','路由器',r'\bmsr\s*-?\d{2,5}[a-z0-9-]*\b|华三[^\r\n]{0,40}路由器|h3c[^\r\n]{0,40}\brouter\b'),
    ('华三 H3C','交换机',r'\bs\d{4,5}[a-z0-9-]*\b|华三[^\r\n]{0,40}交换机|h3c[^\r\n]{0,40}\bswitch\b'),
    ('华三 H3C','防火墙',r'secpath\s+f\d{2,5}[a-z0-9-]*|secpath[^\r\n]{0,40}firewall|华三[^\r\n]{0,40}防火墙'),
    ('中兴 ZTE','路由器',r'\bzsr(?:\s+v\d)?\b|zxr10[\s-]+(?:t8000|m6000|v6000|dn12000|6800|5800|900\b|1800|2800|3800)[a-z0-9-]*|中兴[^\r\n]{0,40}路由器'),
    ('中兴 ZTE','交换机',r'zxr10[\s-]+(?:9900|8900|5960)[a-z0-9-]*|中兴[^\r\n]{0,40}交换机|zte[^\r\n]{0,40}\bswitch\b'),
    ('深信服','防火墙',r'\bngaf\b|\bngfw\b|\baf-?\d{3,5}[a-z0-9-]*\b|下一代防火墙'),
    ('深信服','上网行为管理设备',r'上网行为管理|internet access management|\biag\b|\bac-\d{3,5}[a-z0-9-]*\b'),
    ('深信服','零信任访问网关',r'\batrust\b|零信任访问'),
    ('深信服','VPN 网关',r'\beasyconnect\b|\bssl[- ]?vpn\b'),
]


def match_enterprise(facts):
    clean=[f for f in facts if not (f['source']=='HTTP title' and re.search(r'下载|教程|文档|support|manual|guide|download|documentation|tutorial|\bdocs?\b',f['text'],re.I))]
    by_port={}
    for fact in clean:by_port.setdefault(fact['port'],[]).append(fact)
    vendors=[];devices=[];models=[];platforms=[];systems=[];evidence=[]
    for port,group in by_port.items():
        text='\n'.join(f['text'] for f in group).lower().replace('_',' ')
        found=[name for name,pattern in VENDORS if re.search(pattern,text)]
        vendors.extend(found)
        for fact in group:
            low=fact['text'].lower().replace('_',' ')
            for name,pattern in VENDORS:
                match=re.search(pattern,low)
                if match:evidence.append(dict(dimension='vendor',candidate=name,match=match.group(0),**fact))
            for name,kind,pattern in RULES:
                if name not in found:continue
                match=re.search(pattern,low)
                if match:
                    devices.append(kind);models.append(name+'：'+match.group(0))
                    evidence.append(dict(dimension='device',candidate=kind,match=name+' / '+match.group(0),**fact))
            for pattern,name in [(r'\bvrp(?=\b|\d)|versatile routing platform','VRP'),(r'\bcomware(?=\b|\d)','Comware')]:
                match=re.search(pattern,low)
                if match:
                    platforms.append(name)
                    evidence.append(dict(dimension='platform',candidate=name,match=match.group(0),**fact))
                    if fact['source'] in ('SSH identification','HTTP Server','service banner'):
                        systems.append(name);evidence.append(dict(dimension='os',candidate=name,match=match.group(0),**fact))
    unique=lambda v:list(dict.fromkeys(v))
    return dict(vendors=unique(vendors),devices=unique(devices),models=unique(models),platforms=unique(platforms),systems=unique(systems),evidence=evidence)
