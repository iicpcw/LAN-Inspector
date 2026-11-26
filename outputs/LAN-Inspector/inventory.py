"""Persistent inventory model: observations never overwrite user annotations."""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import uuid


def now():
    return datetime.datetime.now().isoformat(timespec='seconds')


class Inventory:
    def __init__(self):
        self.assets = {}
        self.networks = []
        self.dirty = False
        self.target_text = ''

    def add_networks(self, text):
        nets = []
        count = set()
        for token in text.replace(',', ' ').split():
            net = ipaddress.ip_network(token, strict=False)
            if net.version != 4 or net.num_addresses > 1024:
                raise ValueError('请输入完整 IPv4/CIDR，单个网段最多 1024 个地址')
            nets.append(str(net))
            count.update(str(ip) for ip in ([net.network_address] if net.prefixlen == 32 else net.hosts()))
        if not nets or len(count) > 1024:
            raise ValueError('每轮最多检测 1024 个地址，请分批添加网段')
        for net in nets:
            if net not in self.networks:self.networks.append(net)
        self.dirty = True
        self.target_text = text
        return sorted(count, key=ipaddress.ip_address)

    def find(self, ip):
        return next((a for a in self.assets.values() if a['ip'] == ip), None)

    def add(self, ip, name='', category='', mac='', note='', manual_state='自动', network=None, os_override=''):
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4:raise ValueError('目前仅支持 IPv4')
        ip = str(parsed)
        if self.find(ip):raise ValueError('该 IP 已存在，请编辑已有设备')
        if network:
            net = ipaddress.ip_network(network, strict=False)
            if parsed not in net:raise ValueError('设备 IP 不属于所填网段')
            network = str(net)
        else:
            candidates = [ipaddress.ip_network(n) for n in self.networks if parsed in ipaddress.ip_network(n)]
            network = str(max(candidates, key=lambda n:n.prefixlen)) if candidates else ip+'/32'
        if network not in self.networks:self.networks.append(network)
        asset = dict(os_override=os_override,id=uuid.uuid4().hex, ip=ip, name=name, category=category, mac=mac, note=note,
                     manual_state=manual_state, network=network, observation={}, last_seen='', last_check='', x=None, y=None)
        self.assets[asset['id']]=asset
        self.dirty=True
        return asset

    def record_gateway(self, ip, source, network=None):
        parsed=ipaddress.IPv4Address(ip)
        if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback:
            return None
        if network and parsed not in ipaddress.ip_network(network,strict=False):network=str(parsed)+'/32'
        asset=self.find(str(parsed)) or self.add(str(parsed),network=network)
        sources=asset.setdefault('gateway_sources',[])
        if source not in sources:sources.append(dict(source))
        asset['gateway_current']=True
        self.dirty=True
        return asset

    def observe(self, row, network=None):
        asset=self.find(row['ip'])
        if asset is None:
            if row['status']=='未确认':return None
            asset=self.add(row['ip'],network=network)
        asset['observation']=dict(row)
        asset['last_check']=now()
        if row['status']=='在线':asset['last_seen']=asset['last_check']
        self.dirty=True
        return asset

    def label(self, asset):
        if asset.get('manual_state','自动')!='自动':return asset['manual_state']
        obs=asset.get('observation',{})
        if not obs:return '未检测'
        # Loaded historical observations cannot establish current availability.
        if obs.get('stale'):return '待刷新（历史记录）'
        state=obs.get('status','未确认')
        return '未确认（曾在线）' if state=='未确认' and asset.get('last_seen') else state

    def displayed(self, asset):
        obs=asset.get('observation',{})
        gateway=bool(asset.get('gateway_sources'))
        role='网关' if asset.get('gateway_current') else '历史配置网关'
        category=asset.get('category') or obs.get('device_type','未知设备')
        if gateway and not asset.get('category'):
            category=role+'（设备类型未确认）' if category in ('未知设备','类型待核实','SSH 设备（类型未知）') else category+'（'+role+'角色）'
        name=asset.get('name') or obs.get('hostname') or ((role+' · '+asset['ip']) if gateway else asset['ip'])
        return dict(name=name, category=category, os_family=asset.get('os_override') or obs.get('os_family','未知'),mac=asset.get('mac') or obs.get('mac') or '未获取', status=self.label(asset))

    def save(self, path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        payload=dict(schema=1,saved_at=now(),target_text=self.target_text,networks=self.networks,assets=list(self.assets.values()))
        temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
        os.replace(str(temporary),str(path))
        self.dirty=False

    @classmethod
    def load(cls,path):
        data=json.loads(Path(path).read_text(encoding='utf-8-sig'))
        if data.get('schema')!=1:raise ValueError('不支持的资产文件版本')
        model=cls()
        model.target_text=str(data.get('target_text',''))
        nets=[str(ipaddress.ip_network(n,strict=False)) for n in data['networks']]
        if any(ipaddress.ip_network(n).version!=4 for n in nets):raise ValueError('仅支持 IPv4')
        model.networks=list(dict.fromkeys(nets))
        if len(data['assets'])>10000:raise ValueError('资产文件超过 10000 台上限')
        for raw in data['assets']:
            asset=model.add(raw['ip'], raw.get('name',''), raw.get('category',''), raw.get('mac',''),raw.get('note',''),raw.get('manual_state','自动'),raw['network'])
            if raw.get('id'):
                del model.assets[asset['id']]
                asset['id']=str(raw['id'])
                if asset['id'] in model.assets:raise ValueError('资产 ID 重复')
                model.assets[asset['id']]=asset
            asset['os_override']=str(raw.get('os_override',''))
            sources=raw.get('gateway_sources',[])
            if not isinstance(sources,list) or any(not isinstance(v,dict) for v in sources):raise ValueError('无效网关来源')
            asset['gateway_sources']=sources
            asset['gateway_current']=False
            for key in ('mac_observations','conflict_events'):
                records=raw.get(key,[])
                if not isinstance(records,list):raise ValueError('无效冲突历史')
                asset[key]=records[-200:]
            for key in ('conflict_last_check','conflict_alert'):
                if isinstance(raw.get(key),dict):asset[key]=raw[key]
            asset['conflict_ack']=float(raw.get('conflict_ack',0))
            obs=raw.get('observation',{})
            if not isinstance(obs,dict):raise ValueError('无效观测字段')
            asset['observation']=dict(obs,stale=True) if obs else {}
            for key in ('last_seen','last_check'):asset[key]=str(raw.get(key,''))
            for key in ('x','y'):
                value=raw.get(key)
                if isinstance(value,(float,int)) and abs(value)<1000000:asset[key]=value
        model.dirty=False
        return model
