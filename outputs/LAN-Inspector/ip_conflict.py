"""Source-interface scoped MAC observations, not proof of simultaneous ownership."""
import datetime
import re
import time


def normalize_mac(value):
    clean=re.sub('[:-]','',str(value)).upper()
    if not re.fullmatch('[0-9A-F]{12}',clean) or clean=='000000000000' or int(clean[:2],16)&1:return ''
    return ':'.join(clean[i:i+2] for i in range(0,12,2))


def sample(ip,source_ip,resolver,stop,count=3):
    observations=[];errors=[]
    for _ in range(count):
        if stop.is_set():break
        try:
            value=normalize_mac(resolver(ip,source_ip))
            if value:observations.append(dict(mac=value,time=time.time(),observed_at=datetime.datetime.now().isoformat(timespec='seconds')))
        except Exception as exc:errors.append(str(exc))
        if stop.wait(.2):break
    return dict(ip=ip,source_ip=source_ip,samples=observations,errors=errors,cancelled=stop.is_set())


def apply(asset,result,clock=None):
    clock=time.time() if clock is None else clock
    scope=result['source_ip'];history=asset.setdefault('mac_observations',[])
    old=[r for r in history if isinstance(r,dict) and r.get('source_ip')==scope and isinstance(r.get('time'),(float,int)) and 0<=clock-r['time']<=600 and r['time']>asset.get('conflict_ack',0)]
    values={r['mac'] for r in result['samples']}
    prior={r['mac'] for r in old}
    if len(values)>1:
        state='疑似 IP 冲突';reason='本轮同一源网卡对同一 IP 观测到多个 MAC；需排查冗余切换、代理 ARP 或设备变更'
    elif values and prior-values:
        state='IP–MAC 变化，需核实';reason='与同一源网卡近 10 分钟历史记录不同；不能证明两台设备同时占用 IP'
    elif values:
        state='本轮仅观测到一个 MAC';reason='未发现变化不代表无冲突，缓存或响应时序可能导致漏检'
    else:
        state='未取得 MAC，无法判断';reason='可能为无响应、权限/网络限制或取消；不能判断是否冲突'
    for observation in result['samples']:
        history.append(dict(observation,source_ip=scope))
    asset['mac_observations']=history[-200:]
    suspicious=state in ('疑似 IP 冲突','IP–MAC 变化，需核实')
    report=dict(state=state,reason=reason,checked_at=datetime.datetime.fromtimestamp(clock).isoformat(timespec='seconds'),source_ip=scope,time=clock,macs=sorted(values),samples=result['samples'],errors=result['errors'],cancelled=result['cancelled'])
    asset['conflict_last_check']=report
    if suspicious:
        asset['conflict_alert']=report
        events=asset.setdefault('conflict_events',[]);events.append(report);asset['conflict_events']=events[-50:]
    return report


def acknowledge(asset):
    asset['conflict_ack']=time.time();asset.pop('conflict_alert',None)
