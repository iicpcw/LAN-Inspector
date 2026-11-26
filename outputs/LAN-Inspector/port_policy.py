"""Site-defined TCP blocking policy; an open port is a finding, not a CVE."""
DEFAULT_POLICY = '22,80,135,443'
SERVICES = {22:'SSH',80:'HTTP',135:'RPC',443:'HTTPS',21:'FTP',23:'Telnet',139:'NetBIOS',445:'SMB',3389:'RDP'}


def assess(opened, tested, policy, errors=()):
    policy = set(policy)
    findings = sorted(set(opened) & policy)
    unchecked = sorted((policy - set(tested)) | (policy & set(errors)))
    if findings:
        status = '常见高危端口未封堵'
    elif unchecked:
        status = '检查不完整'
    elif policy:
        status = '未发现策略端口可连接'
    else:
        status = '未配置封堵规则'
    detail = ''
    if findings:
        detail = '常见高危端口未封堵：' + ', '.join('TCP %d (%s)' % (p,SERVICES.get(p,'自定义服务')) for p in findings) + '；违反本次配置的内网封堵规则'
    if unchecked:
        detail += ('；' if detail else '') + '未完成检查：' + ','.join(map(str,unchecked))
    if not detail:
        detail = '仅反映当前扫描位置的 TCP 连接结果；超时或不可达不能证明已封堵' if policy else '未配置检查端口'
    return dict(audit_status=status, risk_ports=','.join(map(str,findings)), audit_detail=detail,
                policy_ports=','.join(map(str,sorted(policy))), unchecked_policy_ports=','.join(map(str,unchecked)))
