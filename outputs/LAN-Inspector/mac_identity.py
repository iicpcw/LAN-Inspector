"""Offline IEEE address assignment lookup; no web queries during scanning."""
import csv
from pathlib import Path
import re
import threading

_DB = None
_ERROR = ''
_LOCK = threading.Lock()


def load_database(path):
    result = {}
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        for row in csv.DictReader(f):
            prefix = row['prefix'].strip().upper()
            if not re.fullmatch(r'(?:[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9})', prefix):
                raise ValueError('无效厂商库前缀：' + prefix)
            result[prefix] = (row['registry'], row['organization'])
    if not result:
        raise ValueError('厂商库为空')
    return result


def database():
    global _DB, _ERROR
    with _LOCK:
        if _DB is None:
            try:
                _DB = load_database(Path(__file__).resolve().parent / 'mac-vendors.csv')
            except (OSError, ValueError, KeyError, csv.Error) as exc:
                _DB, _ERROR = {}, '厂商库不可用：' + str(exc)
    return _DB


def manufacturer_hint(organization):
    low = organization.lower()
    for names, hint in [
        (('apple',), 'Apple 设备：可能为 iPhone/iPad/Mac/其他产品，不能确定 iOS'),
        (('samsung',), 'Samsung 设备：可能为手机/平板/电视等，不能确定 Android'),
        (('xiaomi', 'beijing xiaomi'), '小米生态设备：可能为手机或 IoT，不能确定 Android'),
        (('huawei',), '华为相关设备：可能为终端/网络设备/IoT，无法据此判定系统'),
        (('oppo', 'vivo', 'oneplus', 'realme', 'honor'), '移动品牌相关设备：可能为手机或其他产品，无法据此判定系统'),
        (('google',), 'Google 相关设备：可能为手机/网络设备/IoT，不能确定 Android'),
        (('intel', 'realtek', 'mediatek', 'qualcomm', 'broadcom'), '网卡/芯片厂商，不能等同整机品牌或系统'),
    ]:
        if any(name in low for name in names):
            return hint
    return '仅为 MAC 地址段注册组织，不能确定整机品牌、型号或系统'


def lookup(address, db=None):
    result = dict(mac_vendor='', mac_scope='', vendor_prefix='', vendor_evidence='', device_hint='')
    if not address:
        result.update(mac_scope='未获取 MAC', device_hint='无 MAC，无法推测厂商')
        return result
    clean = re.sub(r'[:.\-]', '', address).upper()
    if not re.fullmatch(r'[0-9A-F]{12}', clean) or clean == '000000000000':
        result.update(mac_scope='无效 MAC', device_hint='无法识别')
        return result
    first = int(clean[:2], 16)
    if first & 1:
        result.update(mac_scope='组播/广播地址', device_hint='不能作为设备厂商依据')
        return result
    if first & 2:
        result.update(mac_scope='本地管理地址（可能为随机/私有 MAC）',
                      device_hint='不能由此区分 iOS、Android、电脑或虚拟机；不查询厂商前缀')
        return result
    db = database() if db is None else db
    result['mac_scope'] = '全局管理地址（仍可能被修改）'
    for size in (9, 7, 6):
        prefix = clean[:size]
        if prefix in db:
            registry, organization = db[prefix]
            result.update(mac_vendor=organization, vendor_prefix=prefix + '/' + str(size*4),
                          vendor_evidence='IEEE ' + registry + ' 最长前缀匹配；注册组织不等于整机厂商',
                          device_hint=manufacturer_hint(organization))
            return result
    result.update(vendor_evidence=_ERROR or '当前离线 IEEE 厂商库未命中', device_hint='厂商未知，不推测系统')
    return result


def mark_shared_mac(rows, address):
    same = [r for r in rows if r.get('mac') == address] if address else []
    if len(same) > 1:
        for row in same:
            row['warning'] = '多个 IP 共用 MAC，可能为代理 ARP；不能据此确认主机在线'
            row['device_hint'] = '共享 MAC：注册厂商可能属于代理/网关，不能归属该 IP 的品牌或设备类型'
            row['vendor_evidence'] = 'MAC 最长前缀匹配仅针对返回的地址；多个 IP 共用该地址，归属待核实'
    return same
