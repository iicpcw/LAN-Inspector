import concurrent.futures as cf
import csv, ctypes, ipaddress, json, platform, queue, re, socket, subprocess, threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import webbrowser
from discovery import identify, save_topology
from port_policy import DEFAULT_POLICY, assess
from mac_identity import lookup, mark_shared_mac
from local_ports import LocalPortWindow
from app_paths import app_dir
from mac_sources import MacContext, active_arp
import datetime


def targets(text):
    items = set()
    for token in text.replace(',', ' ').split():
        net = ipaddress.ip_network(token, strict=False)
        if net.version != 4 or net.num_addresses > 1024:
            raise ValueError('仅支持 IPv4，单次最多 1024 个地址')
        items.update([str(net.network_address)] if net.prefixlen == 32 else (str(ip) for ip in net.hosts()))
    if not items or len(items) > 1024:
        raise ValueError('请输入 IP 或 CIDR，单次最多 1024 个地址')
    return sorted(items, key=ipaddress.ip_address)


def ports(text):
    items = set()
    for token in text.replace(' ', '').split(','):
        bounds = token.split('-')
        lo, hi = (int(token), int(token)) if len(bounds) == 1 else map(int, bounds)
        if not 1 <= lo <= hi <= 65535:
            raise ValueError('端口应为 1–65535')
        items.update(range(lo, hi + 1))
    return sorted(items)


def valid_ping_reply(output, ip):
    # Require a reply line from the requested address, with TTL and payload.
    # Exit status alone also accepts some Windows unreachable responses.
    address = re.compile(rb'(?<![0-9.])' + re.escape(ip.encode('ascii')) + rb'(?![0-9.])')
    return any(address.search(line) and re.search(rb'\bttl[= ]+\d+', line, re.I)
               and re.search(rb'[=:]\s*\d+.*\bttl', line, re.I)
               for line in output.splitlines())


def ping(ip, timeout):
    win = platform.system() == 'Windows'
    args = ['ping', '-n', '1', '-w', str(int(timeout*1000)), ip] if win else ['ping', '-n', '-c', '1', ip]
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout+1, creationflags=0x08000000 if win else 0)
        return p.returncode == 0 and valid_ping_reply(p.stdout, ip)
    except (OSError, subprocess.TimeoutExpired):
        return False


def mac(ip, source_ip=None):
    return active_arp(ip,source_ip)


def inspect(ip, selected, timeout, stop, fingerprint=True, policy=None, resolve_mac=True):
    if stop.is_set():
        return None
    policy = ports(DEFAULT_POLICY) if policy is None else policy
    alive, opened, attempts = ping(ip, timeout), [], 0
    tested, errors = [], []
    for port in selected:
        if stop.is_set():
            break
        attempts += 1
        tested.append(port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                code = s.connect_ex((ip, port))
                if code == 0:
                    opened.append(port)
                elif code in (13, 1, 10013, 10022):
                    errors.append(port)
        except OSError:
            errors.append(port)
    address = '' if stop.is_set() or not resolve_mac else mac(ip)
    evidence = ', '.join(name for name, ok in [('ICMP 目标响应', alive), ('TCP 连接成功', bool(opened))] if ok)
    status = '在线' if evidence else ('仅 ARP 响应' if address else '未确认')
    if address:
        evidence = (evidence + '；' if evidence else '') + 'ARP 地址（可能为代理）'
    row = dict(ip=ip, status=status, mac=address, ports=','.join(map(str, opened)), evidence=evidence or '无响应不代表离线', warning='', scan='已取消' if stop.is_set() else '完成', attempted=attempts)
    row.update(mac_source='SendARP' if address else '',mac_state='ARP 解析' if address else '未获取',mac_confidence='中' if address else '未知',mac_candidates=[],mac_errors=[],mac_note='',mac_interface='',mac_checked_at=datetime.datetime.now().isoformat(timespec='seconds'))
    row.update(identify(ip, opened, timeout, stop) if fingerprint and opened and not stop.is_set()
               else dict(device_type='未知设备', confidence='未知', fingerprint='无指纹或未启用识别', service_banners='',os_family='未知',os_confidence='未知',identification_evidence=[],device_candidates=[],os_candidates=[],service_facts=[],device_vendor='未知',vendor_confidence='未知',vendor_candidates=[],model_hint='未知',platform_hint='未知'))
    row.update(lookup(address))
    row.update(assess(opened, tested, policy, errors))
    return row


class App:
    def __init__(self, root):
        self.root, self.rows = root, []
        self.events, self.stop = queue.Queue(), threading.Event()
        self.running = False
        self.report_path = None
        self.scan_target = ''
        root.title('内网巡检台 · LAN Inspector 2.2')
        root.geometry('1080x680')
        root.minsize(850, 540)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', rowheight=28)
        frame = ttk.Frame(root, padding=20)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='内网巡检台', font=('Microsoft YaHei UI', 22, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='离线运行 · IPv4 主机发现 · TCP 端口扫描 · MAC 查询').pack(anchor='w', pady=(5, 18))
        config = ttk.LabelFrame(frame, text='扫描配置', padding=12)
        config.pack(fill='x')
        self.target = tk.StringVar(value='127.0.0.1')
        self.selected = tk.StringVar(value='22,80,135,139,443,445,3389,5985,5986,8000,8080,8443')
        self.timeout = tk.StringVar(value='0.5')
        self.workers = tk.StringVar(value='32')
        self.policy = tk.StringVar(value=DEFAULT_POLICY)
        self.tcp = tk.BooleanVar(value=True)
        self.fingerprint_enabled = tk.BooleanVar(value=True)
        for row, label, var in [(0, '目标 IP / CIDR', self.target), (1, 'TCP 端口', self.selected)]:
            ttk.Label(config, text=label, width=18).grid(row=row, column=0, sticky='w', pady=5)
            ttk.Entry(config, textvariable=var).grid(row=row, column=1, columnspan=5, sticky='ew')
        config.columnconfigure(1, weight=1)
        ttk.Label(config, text='目标示例：192.168.1.0/24；多个目标用空格分隔；端口支持 80,443,8000-8100').grid(row=2, column=1, columnspan=5, sticky='w')
        ttk.Label(config, text='超时（秒）').grid(row=3, column=0, sticky='w', pady=10)
        ttk.Entry(config, textvariable=self.timeout, width=7).grid(row=3, column=1, sticky='w')
        ttk.Label(config, text='并发主机').grid(row=3, column=2)
        ttk.Entry(config, textvariable=self.workers, width=7).grid(row=3, column=3)
        ttk.Checkbutton(config, text='扫描 TCP', variable=self.tcp).grid(row=3, column=4, padx=12)
        ttk.Checkbutton(config, text='识别设备（读取 SSH / Web 指纹）', variable=self.fingerprint_enabled).grid(row=4, column=1, columnspan=4, sticky='w')
        ttk.Label(config, text='要求封堵的 TCP 端口').grid(row=5, column=0, sticky='w', pady=5)
        ttk.Entry(config, textvariable=self.policy).grid(row=5, column=1, columnspan=5, sticky='ew')
        ttk.Label(config, text='按本单位规则告警；启用 TCP 时自动覆盖这些端口；留空不检查。').grid(row=6, column=1, columnspan=5, sticky='w')
        bar = ttk.Frame(frame)
        bar.pack(fill='x', pady=12)
        self.start_btn = ttk.Button(bar, text='开始扫描', command=self.start)
        self.start_btn.pack(side='left')
        self.stop_btn = ttk.Button(bar, text='停止', command=self.cancel, state='disabled')
        self.stop_btn.pack(side='left', padx=8)
        ttk.Button(bar, text='导出 CSV / JSON', command=self.export).pack(side='right')
        ttk.Button(bar, text='打开拓扑图', command=self.open_topology).pack(side='right', padx=8)
        ttk.Button(bar, text='本机端口管理', command=lambda: LocalPortWindow(self.root)).pack(side='left', padx=8)
        self.progress = ttk.Progressbar(frame)
        self.progress.pack(fill='x', pady=(0, 10))
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill='both', expand=True)
        cols = ('audit_status', 'risk_ports', 'ip', 'status', 'mac','mac_source','mac_state', 'mac_vendor', 'device_hint', 'mac_scope', 'ports', 'evidence', 'scan', 'warning', 'device_type','device_vendor','model_hint','platform_hint','os_family','os_confidence', 'confidence', 'fingerprint')
        self.table = ttk.Treeview(table_frame, columns=cols, show='headings')
        self.table.tag_configure('risk', foreground='#b42318', background='#fff0ed')
        for key, title, width in zip(cols, ['封堵检查', '未封堵端口', 'IP 地址', '状态', 'MAC 地址','MAC 来源','MAC 获取状态', 'MAC 注册厂商', '设备推测与限制', 'MAC 属性', '开放 TCP 端口', '在线依据', '扫描状态', '提示', '设备类型','服务标识厂商','产品线索','软件平台线索', 'OS', 'OS 置信度','置信度', '识别依据'], [190,130,120,110,150,190,170,180,300,240,130,230,75,210,180,140,210,130,160,85,70,280]):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=60)
        scroll = ttk.Scrollbar(table_frame, command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        hscroll = ttk.Scrollbar(table_frame, orient='horizontal', command=self.table.xview)
        self.table.configure(xscrollcommand=hscroll.set)
        hscroll.pack(side='bottom', fill='x')
        self.table.pack(fill='both', expand=True)
        self.table.bind('<Double-1>', self.show_details)
        self.status = tk.StringVar(value='就绪。仅 ARP 响应不计为在线；多个 IP 共用 MAC 时提示可能存在代理 ARP。')
        ttk.Label(frame, textvariable=self.status, wraplength=1000).pack(anchor='w', pady=(12, 0))
        self.poll_timer = root.after(100, self.poll)
        root.protocol('WM_DELETE_WINDOW', self.close)

    def start(self):
        if self.running:
            return
        try:
            addresses = targets(self.target.get())
            policy = ports(self.policy.get()) if self.policy.get().strip() else []
            selected = sorted(set(ports(self.selected.get())) | set(policy)) if self.tcp.get() else []
            timeout, workers = float(self.timeout.get()), int(self.workers.get())
            if not 0.1 <= timeout <= 5 or not 1 <= workers <= 128:
                raise ValueError('超时为 0.1–5 秒，并发主机为 1–128')
        except ValueError as exc:
            messagebox.showerror('配置错误', str(exc))
            return
        self.scan_target = self.target.get()
        self.report_path = None
        fingerprint = self.fingerprint_enabled.get()
        self.rows.clear()
        self.table.delete(*self.table.get_children())
        self.stop.clear()
        self.running = True
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.progress.configure(maximum=len(addresses), value=0)
        self.status.set('扫描中：{} 个目标，每台 {} 个端口'.format(len(addresses), len(selected)))
        def run():
            try:
                context=MacContext();context.refresh();collected=[]
                def probe(ip):
                    row=inspect(ip,selected,timeout,self.stop,fingerprint,policy,False)
                    if row:
                        nb=bool(set(map(int,row['ports'].split(','))) & {139,445}) if row['ports'] else False
                        return context.enrich(row,self.stop,netbios=nb or 'Windows' in row.get('os_family',''))
                with cf.ThreadPoolExecutor(max_workers=workers) as pool:
                    jobs = [pool.submit(probe, ip) for ip in addresses]
                    for job in cf.as_completed(jobs):
                        row = job.result()
                        if row:
                            collected.append(row)
                            self.events.put(('row', row))
                missing=[r for r in collected if not r.get('mac')]
                if missing and not self.stop.is_set():
                    context.refresh()
                    self.events.put(('mac_updates',[context.enrich(r,self.stop,active=False) for r in missing]))
            except Exception as exc:
                self.events.put(('error', str(exc)))
            finally:
                self.events.put(('done', None))
        threading.Thread(target=run, daemon=True).start()

    def cancel(self):
        self.stop.set()
        self.status.set('正在停止，等待当前网络操作结束…')

    def poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == 'row':
                    self.rows.append(data)
                    self.table.insert('', 'end', iid=data['ip'], values=[data.get(k, '') for k in self.table['columns']], tags=('risk',) if data.get('risk_ports') else ())
                    if data['mac']:
                        same = mark_shared_mac(self.rows, data['mac'])
                        if len(same) > 1:
                            for row in same:
                                row['warning'] = '多个 IP 共用 MAC，可能为代理 ARP；不能据此确认主机在线'
                                self.table.item(row['ip'], values=[row[k] for k in self.table['columns']])
                    self.progress.configure(value=len(self.rows))
                    if not self.stop.is_set():
                        self.status.set('已处理 {} 台，在线 {} 台'.format(len(self.rows), sum(r['status']=='在线' for r in self.rows)))
                elif kind == 'mac_updates':
                    for updated in data:
                        original=next((r for r in self.rows if r['ip']==updated['ip']),None)
                        if original:
                            original.update(updated)
                            mark_shared_mac(self.rows,updated.get('mac'))
                    for row in self.rows:
                        self.table.item(row['ip'],values=[row.get(k,'') for k in self.table['columns']])
                elif kind == 'error':
                    messagebox.showerror('扫描异常', data)
                elif kind == 'done':
                    self.running = False
                    self.start_btn.configure(state='normal')
                    self.stop_btn.configure(state='disabled')
                    if not self.stop.is_set() and self.rows:
                        self.create_topology()
                    self.status.set('{}：已处理 {} 台，在线 {} 台'.format('已停止' if self.stop.is_set() else '完成', len(self.rows), sum(r['status']=='在线' for r in self.rows)) + '；未封堵告警 {} 台'.format(sum(bool(r.get('risk_ports')) for r in self.rows)) + ('；拓扑已生成，点击“打开拓扑图”查看' if self.report_path else ''))
        except queue.Empty:
            pass
        self.poll_timer = self.root.after(100, self.poll)

    def export(self):
        if not self.rows:
            messagebox.showinfo('导出', '暂无结果')
            return
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV','*.csv'),('JSON','*.json')])
        if not path:
            return
        try:
            is_json = path.lower().endswith('.json')
            with open(path, 'w', encoding='utf-8' if is_json else 'utf-8-sig', newline='') as out:
                rows = sorted(self.rows, key=lambda r: ipaddress.ip_address(r['ip']))
                if is_json:
                    json.dump(rows, out, ensure_ascii=False, indent=2)
                else:
                    writer = csv.DictWriter(out, fieldnames=list(rows[0]))
                    writer.writeheader()
                    writer.writerows(rows)
        except OSError as exc:
            messagebox.showerror('导出失败', str(exc))

    def create_topology(self):
        try:
            self.report_path = save_topology(self.rows, self.scan_target, app_dir() / 'reports')
        except (OSError, ValueError) as exc:
            messagebox.showerror('拓扑生成失败', str(exc))

    def open_topology(self):
        if self.running:
            messagebox.showinfo('拓扑图', '请等待扫描结束，或停止后查看已完成的部分结果')
            return
        if not self.rows:
            messagebox.showinfo('拓扑图', '请先扫描')
            return
        if not self.report_path:
            self.create_topology()
        if self.report_path:
            webbrowser.open(self.report_path.resolve().as_uri())

    def show_details(self, event=None):
        selected = self.table.selection()
        if not selected:
            return
        row = next(r for r in self.rows if r['ip'] == selected[0])
        win = tk.Toplevel(self.root)
        win.title('设备详情 · ' + row['ip'])
        box = tk.Text(win, width=100, height=30, wrap='word')
        box.pack(fill='both', expand=True)
        box.insert('end', '\n\n'.join(k + ': ' + str(v) for k, v in row.items()))
        box.configure(state='disabled')

    def close(self):
        if any(getattr(child, '_local_ports_busy', False) for child in self.root.winfo_children()):
            messagebox.showinfo('操作进行中', '请等待本机端口管理完成当前操作后再退出。')
            return
        self.stop.set()
        try:self.root.after_cancel(self.poll_timer)
        except tk.TclError:pass
        self.root.destroy()


if __name__ == '__main__':
    if '--self-test' in __import__('sys').argv:
        from build_smoke import run_smoke
        run_smoke()
        raise SystemExit(0)
    root = tk.Tk()
    if '--local-ports' in __import__('sys').argv:
        root.withdraw()
        manager = LocalPortWindow(root)
        def close_manager():
            if manager.busy:
                manager.close()
            else:
                root.destroy()
        manager.win.protocol('WM_DELETE_WINDOW', close_manager)
    elif '--scanner' in __import__('sys').argv:
        App(root)
    elif '--topology' in __import__('sys').argv:
        from dashboard import Dashboard
        argv=__import__('sys').argv
        asset_file=argv[argv.index('--inventory')+1] if '--inventory' in argv and argv.index('--inventory')+1<len(argv) else None
        Dashboard(root, inspect, advanced=lambda: App(tk.Toplevel(root)), local_ports=lambda: LocalPortWindow(root),asset_file=asset_file,auto_scan='--no-auto-scan' not in argv)
    else:
        from home import Home
        Home(root, inspect, App, LocalPortWindow)
    root.mainloop()

