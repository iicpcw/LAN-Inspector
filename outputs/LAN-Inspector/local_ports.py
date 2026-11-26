"""Local-only Windows endpoint inventory and reversible inbound firewall rules."""
import base64
import ctypes
import datetime
import json
import os
from pathlib import Path
import platform
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from app_paths import app_dir, launch_args


BASE = Path(__file__).resolve().parent


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def validate_requests(items):
    result = set()
    for item in items:
        proto, port = item['protocol'], item['port']
        if proto not in ('TCP', 'UDP') or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('无效的协议或端口')
        result.add((proto, port))
    return [dict(protocol=proto, port=port) for proto, port in sorted(result)]


def run_action(action, items=()):
    if platform.system() != 'Windows':
        raise RuntimeError('本机端口管理仅支持 Windows 10/11 及带 NetTCPIP/NetSecurity 的 Windows Server')
    if action not in ('scan', 'block', 'remove'):
        raise ValueError('不支持的操作')
    items = validate_requests(items)
    if action != 'scan' and not items:
        raise ValueError('请先勾选端口或规则')
    if action != 'scan' and not is_admin():
        raise PermissionError('请使用“以管理员身份重新打开”按钮，在新窗口执行封堵或撤销')
    payload = base64.b64encode(json.dumps(items).encode('utf-8')).decode('ascii')
    executable = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
    args = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', str(BASE / 'local_ports.ps1'), '-Action', action, '-Payload', payload]
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, creationflags=0x08000000)
    except subprocess.TimeoutExpired:
        raise RuntimeError('操作超时，结果未确认。若已提交封堵/撤销，请刷新“本工具规则”核实，勿按失败推断未发生修改。')
    try:
        response = json.loads(p.stdout.decode('utf-8-sig'))
    except (ValueError, UnicodeError):
        raise RuntimeError('PowerShell 未返回有效结果：' + p.stderr.decode('utf-8','replace')[:1500])
    if not response.get('ok'):
        raise RuntimeError(response.get('error', '操作失败'))
    return response


def elevate():
    arguments = subprocess.list2cmdline(launch_args('--local-ports'))
    result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, arguments, str(app_dir()), 1)
    if result <= 32:
        raise RuntimeError('未能以管理员启动（可能取消了 UAC 授权）')


class LocalPortWindow:
    def __init__(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title('本机 Windows 端口管理')
        self.win.geometry('1180x760')
        self.win.minsize(900, 600)
        self.events = queue.Queue()
        self.busy = False
        self.endpoints, self.rules = {}, {}
        self.checked_endpoints, self.checked_rules = set(), set()
        frame = ttk.Frame(self.win, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='本机监听端口与入站封堵', font=('Microsoft YaHei UI',18,'bold')).pack(anchor='w')
        ttk.Label(frame, text='列出 TCP 监听 / UDP 绑定，不等于远端可访问。封堵针对所选协议和端口的所有本机地址、所有配置文件及所有进程。', wraplength=1100).pack(anchor='w', pady=8)
        bar = ttk.Frame(frame); bar.pack(fill='x', pady=8)
        self.buttons = []
        for label, command in [('扫描 / 刷新', lambda:self.submit('scan')),('勾选全部监听端口',self.select_all),('清空勾选',self.clear_checks),('封堵勾选端口',lambda:self.mutate('block')),('撤销勾选的本工具规则',lambda:self.mutate('remove'))]:
            button = ttk.Button(bar,text=label,command=command);button.pack(side='left',padx=3);self.buttons.append(button)
        ttk.Button(frame,text='以管理员身份重新打开',command=self.admin_open).pack(anchor='w')
        self.profile_text=tk.StringVar(value='正在读取防火墙配置…')
        ttk.Label(frame,textvariable=self.profile_text,wraplength=1100).pack(anchor='w',pady=8)
        notebook=ttk.Notebook(frame);notebook.pack(fill='both',expand=True)
        self.endpoint_table=self.make_table(notebook,'监听端口',('check','protocol','port','address','pid','process','state'),('勾选','协议','端口','绑定地址','PID','进程','状态'),(55,60,70,230,85,240,130))
        self.rule_table=self.make_table(notebook,'本工具规则（可撤销）',('check','protocol','port','enabled','active','direction','action','profile'),('勾选','协议','端口','启用','ActiveStore 可见','方向','动作','配置文件'),(55,65,80,85,150,100,100,140))
        self.endpoint_table.bind('<Button-1>',lambda e:self.toggle(e,False))
        self.rule_table.bind('<Button-1>',lambda e:self.toggle(e,True))
        self.endpoint_table.bind('<space>',lambda e:self.toggle_selected(False))
        self.rule_table.bind('<space>',lambda e:self.toggle_selected(True))
        self.log=tk.Text(frame,height=7,wrap='word');self.log.pack(fill='x',pady=(10,0))
        self.status=tk.StringVar(value='就绪；管理员权限：'+('是' if is_admin() else '否（可扫描，封堵需提权）'))
        ttk.Label(frame,textvariable=self.status,wraplength=1100).pack(anchor='w',pady=8)
        self.win.protocol('WM_DELETE_WINDOW', self.close)
        self.win.after(100,self.poll)
        self.win.after(150,lambda:self.submit('scan'))

    def close(self):
        if self.busy:
            messagebox.showinfo('操作进行中', '请等待操作完成，以便查看每个端口的处理结果。', parent=self.win)
            return
        self.win.destroy()

    def make_table(self,notebook,label,columns,titles,widths):
        pane=ttk.Frame(notebook);notebook.add(pane,text=label)
        table=ttk.Treeview(pane,columns=columns,show='headings')
        for key,title,width in zip(columns,titles,widths):
            table.heading(key,text=title);table.column(key,width=width,minwidth=50)
        vertical=ttk.Scrollbar(pane,orient='vertical',command=table.yview);vertical.pack(side='right',fill='y')
        horizontal=ttk.Scrollbar(pane,orient='horizontal',command=table.xview);horizontal.pack(side='bottom',fill='x')
        table.configure(yscrollcommand=vertical.set,xscrollcommand=horizontal.set)
        table.pack(fill='both',expand=True)
        return table

    def toggle(self,event,rules):
        if self.busy:return
        table=self.rule_table if rules else self.endpoint_table
        if table.identify_column(event.x)!='#1':return
        iid=table.identify_row(event.y)
        self.flip(iid,rules)

    def toggle_selected(self,rules):
        table=self.rule_table if rules else self.endpoint_table
        for iid in table.selection():self.flip(iid,rules)
        return 'break'

    def flip(self,iid,rules):
        if not iid or self.busy:return
        checked=self.checked_rules if rules else self.checked_endpoints
        table=self.rule_table if rules else self.endpoint_table
        if iid in checked:checked.remove(iid)
        else:checked.add(iid)
        table.set(iid,'check','☑' if iid in checked else '☐')

    def select_all(self):
        if self.busy:return
        self.checked_endpoints=set(self.endpoints)
        for iid in self.endpoints:self.endpoint_table.set(iid,'check','☑')

    def clear_checks(self):
        if self.busy:return
        self.checked_endpoints.clear();self.checked_rules.clear()
        for table in (self.endpoint_table,self.rule_table):
            for iid in table.get_children():table.set(iid,'check','☐')

    def admin_open(self):
        if platform.system()!='Windows':
            messagebox.showinfo('仅支持 Windows','请在 Windows 上使用此功能',parent=self.win);return
        try:elevate()
        except (RuntimeError,OSError) as exc:messagebox.showerror('启动失败',str(exc),parent=self.win)

    def mutate(self,action):
        if self.busy:return
        if not is_admin():
            messagebox.showinfo('需要管理员权限','请点击“以管理员身份重新打开”，在 UAC 授权后的新窗口重新扫描并勾选。',parent=self.win);return
        try:
            if action=='block':
                items=validate_requests([self.endpoints[iid] for iid in self.checked_endpoints])
            else:
                items=validate_requests([self.rules[iid] for iid in self.checked_rules])
        except (ValueError,KeyError) as exc:
            messagebox.showerror('选择无效',str(exc),parent=self.win);return
        if not items:
            messagebox.showinfo('尚未勾选','请点击对应表格首列的方框勾选。',parent=self.win);return
        listing=', '.join(r['protocol']+'/'+str(r['port']) for r in items)
        prompt=('将创建持久入站阻断规则，覆盖所有本机地址、所有进程和全部网络配置文件：\n' if action=='block' else '仅删除以下端口由本工具创建的规则；其他规则保持生效：\n')+listing
        if action=='block' and any(r['port'] in (22,135,445,3389,5985,5986) for r in items):
            prompt+='\n所选端口包含远程管理/共享端口，可能中断管理或业务访问。'
        if messagebox.askyesno('确认封堵' if action=='block' else '确认撤销',prompt,parent=self.win):
            self.submit(action,items)

    def submit(self,action,items=()):
        if self.busy or not self.win.winfo_exists():return
        self.busy=True
        self.win._local_ports_busy=True
        for button in self.buttons:button.configure(state='disabled')
        self.status.set('正在'+{'scan':'读取本机端口和规则','block':'创建封堵规则','remove':'撤销规则'}[action]+'…')
        def worker():
            try:self.events.put(('ok',(action,run_action(action,items))))
            except Exception as exc:self.events.put(('error',str(exc)))
        threading.Thread(target=worker,daemon=True).start()

    def render(self,data):
        self.endpoints.clear();self.rules.clear();self.checked_endpoints.clear();self.checked_rules.clear()
        for table in (self.endpoint_table,self.rule_table):table.delete(*table.get_children())
        for index,row in enumerate(data.get('endpoints',[])):
            iid='e'+str(index);self.endpoints[iid]=row
            self.endpoint_table.insert('','end',iid=iid,values=('☐',row['protocol'],row['port'],row['address'],row['pid'],row.get('process') or '未知/进程已退出',row['state']))
        for index,row in enumerate(data.get('rules',[])):
            # Only canonical protocol/port rules can be selected for removal.
            import re
            match=re.fullmatch(r'LANInspector\.LocalPortBlock\.v1\.(TCP|UDP)\.([0-9]{1,5})',row['name'])
            if not match:continue
            iid='r'+str(index);self.rules[iid]=dict(protocol=match.group(1),port=int(match.group(2)))
            self.rule_table.insert('','end',iid=iid,values=('☐',row['protocol'],row['port'],row['enabled'],'是' if row['activeStore'] else '否',row['direction'],row['action'],row['profile']))
        profiles=data.get('profiles',[])
        summary='；'.join(p['name']+': Enabled='+p['enabled']+', 本地规则合并='+p['localMerge'] for p in profiles)
        self.profile_text.set((summary or '未读取到防火墙配置')+'。规则存在不代表已验证网络封堵；防火墙关闭或组织策略禁止本地规则时可能不生效。')
        for warning in data.get('warnings',[]):self.log.insert('end',warning+'\n')

    def poll(self):
        if not self.win.winfo_exists():return
        try:
            while True:
                kind,value=self.events.get_nowait()
                self.busy=False
                self.win._local_ports_busy=False
                for button in self.buttons:button.configure(state='normal')
                if kind=='error':
                    self.status.set('操作未确认/失败：'+value)
                    self.log.insert('end',value+'\n')
                    messagebox.showerror('本机端口管理',value,parent=self.win)
                else:
                    action,response=value
                    self.render(response['data'])
                    for row in response.get('results',[]):
                        self.log.insert('end',('%s/%s %s: %s\n' % (row['protocol'],row['port'],'成功' if row['success'] else '失败',row['message'])))
                    failed=sum(not row['success'] for row in response.get('results',[]))
                    self.status.set('读取完成：{} 条监听/绑定记录，{} 条本工具规则。'.format(len(self.endpoints),len(self.rules)) + ('本次操作 {} 项失败；详情见下方。'.format(failed) if action!='scan' else '请勾选需封堵端口。'))
                    try:
                        folder=app_dir()/'reports';folder.mkdir(exist_ok=True)
                        stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
                        (folder/('local-ports-'+stamp+'.json')).write_text(json.dumps(dict(action=action,timestamp=stamp,response=response),ensure_ascii=False,indent=2),encoding='utf-8')
                    except OSError as exc:self.log.insert('end','本地报告保存失败：'+str(exc)+'\n')
                    self.log.see('end')
        except queue.Empty:pass
        self.win.after(100,self.poll)
