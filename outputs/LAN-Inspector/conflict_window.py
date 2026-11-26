"""Sub-feature launched from the topology; does not modify the ARP table."""
import concurrent.futures as cf
import ipaddress
import json
import datetime
from pathlib import Path
from arp_cache import clear_cache, elevate_topology, is_admin
import queue
import threading
import tkinter as tk
from tkinter import ttk,messagebox
from ip_conflict import sample,apply,acknowledge
from mac_identity import lookup


class ConflictWindow:
    def __init__(self,dashboard,resolver):
        self.dashboard=dashboard;self.resolver=resolver;self.busy=False;self.stop=threading.Event();self.events=queue.Queue()
        self.win=tk.Toplevel(dashboard.root);self.win.title('拓扑子功能 · IP 冲突检测');self.win.geometry('1060x700')
        frame=ttk.Frame(self.win,padding=16);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='疑似 IP 冲突 / MAC 变化检测',font=('Microsoft YaHei UI',17,'bold')).pack(anchor='w')
        ttk.Label(frame,text='仅检测所选网卡的直连 IPv4 地址。每个地址采集 3 次；可能命中 ARP 缓存，不保证发现所有冲突。不清空缓存、不修改网络配置。',wraplength=1000).pack(anchor='w',pady=8)
        self.source=tk.StringVar()
        self.adapters=list(dashboard.adapters)
        self.combo=ttk.Combobox(frame,textvariable=self.source,state='readonly',width=100,values=[r['name']+' | '+r['ip']+' | '+r['network'] for r in self.adapters]);self.combo.pack(fill='x')
        if self.adapters:self.combo.current(max(0,dashboard.adapter_combo.current()))
        self.target=tk.StringVar(value=dashboard.model.assets[dashboard.selected]['ip'] if dashboard.selected in dashboard.model.assets else dashboard.target.get())
        row=ttk.Frame(frame);row.pack(fill='x',pady=10)
        ttk.Label(row,text='目标 IP / CIDR').pack(side='left');ttk.Entry(row,textvariable=self.target,width=45).pack(side='left',fill='x',expand=True,padx=8)
        self.start=ttk.Button(row,text='开始检测',command=self.run);self.start.pack(side='left',padx=4)
        ttk.Button(row,text='停止',command=self.stop.set).pack(side='left',padx=4)
        ttk.Button(row,text='已核实，清除选中告警',command=self.clear).pack(side='left',padx=4)
        ttk.Button(frame,text='清除 ARP 缓存…',command=self.clear_arp).pack(anchor='w',pady=4)
        self.table=ttk.Treeview(frame,columns=('ip','state','macs'),show='headings')
        for key,title,width in [('ip','IP',160),('state','检测结果',260),('macs','本轮 MAC',520)]:self.table.heading(key,text=title);self.table.column(key,width=width)
        scroll=ttk.Scrollbar(frame,command=self.table.yview);self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y');self.table.pack(fill='both',expand=True)
        self.table.tag_configure('alert',foreground='#9c2780');self.table.bind('<<TreeviewSelect>>',self.details)
        self.text=tk.Text(frame,height=9,wrap='word');self.text.pack(fill='x',pady=8)
        self.status=tk.StringVar(value='结果保存于拓扑资产文件；跨网段不能直接进行 ARP 冲突检测。')
        ttk.Label(frame,textvariable=self.status,wraplength=1000).pack(anchor='w')
        self.win.protocol('WM_DELETE_WINDOW',self.close);self.timer=self.win.after(100,self.poll)

    def run(self):
        if self.busy:return
        if self.dashboard.running or self.dashboard.mac_busy:messagebox.showinfo('扫描进行中','请先停止或等待拓扑扫描完成，再检测冲突。',parent=self.win);return
        try:
            from inventory import Inventory
            requests=Inventory().add_networks(self.target.get())
            index=self.combo.current()
            if index<0:raise ValueError('请先在拓扑中识别本机网卡，再选择源网卡')
            adapter=self.adapters[index];net=ipaddress.ip_network(adapter['network'])
            if any(ipaddress.ip_address(ip) not in net for ip in requests):raise ValueError('目标必须位于所选网卡的直连网段；跨路由不支持此检测')
        except ValueError as exc:messagebox.showerror('无法检测',str(exc),parent=self.win);return
        self.busy=True;self.dashboard.conflict_busy=True;self.win._conflict_busy=True;self.stop.clear();self.start.configure(state='disabled')
        self.table.delete(*self.table.get_children());self.checked=0;self.total=len(requests);self.network=adapter['network']
        self.status.set('正在采集 MAC，等待网络操作完成…')
        def work():
            try:
                with cf.ThreadPoolExecutor(max_workers=16) as pool:
                    jobs=[pool.submit(sample,ip,adapter['ip'],self.resolver,self.stop) for ip in requests]
                    for future in cf.as_completed(jobs):self.events.put(('row',future.result()))
            except Exception as exc:self.events.put(('error',str(exc)))
            finally:self.events.put(('done',None))
        threading.Thread(target=work,daemon=True).start()

    def clear_arp(self):
        if self.busy or self.dashboard.running or self.dashboard.mac_busy:
            messagebox.showinfo('操作进行中','请先停止并等待扫描或冲突检测结束。',parent=self.win);return
        index=self.combo.current()
        if index<0:messagebox.showinfo('未选择网卡','请先选择源网卡。',parent=self.win);return
        adapter=dict(self.adapters[index])
        if not is_admin():
            if messagebox.askyesno('需要管理员权限','先保存资产，再以管理员身份重新打开拓扑？新窗口不会自动清理，需再次选择并确认。',parent=self.win):
                if not self.dashboard.save(quiet=True):return
                try:
                    elevate_topology(self.dashboard.file)
                    self.close();self.dashboard.close()
                except (OSError,RuntimeError) as exc:messagebox.showerror('提权启动失败',str(exc),parent=self.win)
            return
        selected=list(self.table.selection())
        dialog=tk.Toplevel(self.win);dialog.title('确认 ARP 缓存清理范围');dialog.transient(self.win);dialog.grab_set()
        ttk.Label(dialog,text='网卡：'+adapter['name']+' | '+adapter['ip']+' | '+adapter['network'],wraplength=650).pack(anchor='w',padx=18,pady=12)
        mode=tk.StringVar(value='selected')
        ttk.Radiobutton(dialog,text='仅选中 IP：'+(', '.join(selected) or '尚未选择，请返回结果表勾选行'),variable=mode,value='selected').pack(anchor='w',padx=18,pady=8)
        ttk.Radiobutton(dialog,text='清除所选网卡的全部活动 ARP 缓存',variable=mode,value='interface').pack(anchor='w',padx=18,pady=8)
        ttk.Label(dialog,text='清理后访问设备时会重新解析 MAC，可能短暂影响连接。不清除持久存储；不清除历史检测证据，也不代表已修复冲突。',wraplength=650).pack(anchor='w',padx=18,pady=12)
        def confirm():
            all_entries=mode.get()=='interface'
            if not all_entries and not selected:messagebox.showinfo('未选中 IP','请返回结果表选中目标 IP。',parent=dialog);return
            dialog.destroy();self.busy=True;self.dashboard.conflict_busy=True;self.win._conflict_busy=True;self.start.configure(state='disabled')
            self.status.set('正在清除所选网卡的活动 ARP 缓存…')
            def work():
                try:self.events.put(('arp_result',clear_cache(adapter,() if all_entries else selected,all_entries)))
                except Exception as exc:self.events.put(('arp_error',str(exc)))
            threading.Thread(target=work,daemon=True).start()
        ttk.Button(dialog,text='确认清理',command=confirm).pack(side='right',padx=18,pady=12)
        ttk.Button(dialog,text='取消',command=dialog.destroy).pack(side='right',pady=12)

    def details(self,event=None):
        selected=self.table.selection()
        if not selected:return
        asset=self.dashboard.model.find(selected[0])
        self.text.delete('1.0','end')
        if asset:
            self.dashboard.selected=asset['id'];self.dashboard.show_details()
            self.text.insert('end',json.dumps(dict(latest=asset.get('conflict_last_check'),history=asset.get('mac_observations'),events=asset.get('conflict_events')),ensure_ascii=False,indent=2))

    def clear(self):
        if self.busy:return
        for ip in self.table.selection():
            asset=self.dashboard.model.find(ip)
            if asset:
                acknowledge(asset);self.dashboard.model.dirty=True
                self.table.item(ip,tags=())
        self.dashboard.save(quiet=True);self.dashboard.draw();self.details()
        self.status.set('选中设备的告警已确认清除；历史记录保留，后续新异常仍会告警。')

    def poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='row':
                    self.checked+=1
                    asset=self.dashboard.model.find(value['ip'])
                    if not asset and value['samples']:
                        observed_mac=value['samples'][-1]['mac']
                        asset=self.dashboard.model.observe(dict(ip=value['ip'],status='仅 ARP 响应',mac=observed_mac,device_type='未知设备',ports='',evidence='冲突检测的 MAC 观测，可能为缓存或代理',**lookup(observed_mac)),network=self.network)
                    if asset:
                        report=apply(asset,value);self.dashboard.model.dirty=True
                        self.table.insert('','end',iid=value['ip'],values=(value['ip'],report['state'],', '.join(report['macs'])),tags=('alert',) if asset.get('conflict_alert') else ())
                    else:self.table.insert('','end',iid=value['ip'],values=(value['ip'],'未取得 MAC，无法判断',''))
                    self.status.set('已处理 {}/{}；无变化不代表无冲突。'.format(self.checked,self.total))
                elif kind=='done':
                    self.busy=False;self.dashboard.conflict_busy=False;self.win._conflict_busy=False;self.start.configure(state='normal')
                    self.dashboard.draw();self.dashboard.save(quiet=True)
                    self.status.set(('已停止' if self.stop.is_set() else '检测完成')+'；结果已保存，点击设备查看证据；不能据此保证无冲突。')
                elif kind in ('arp_result','arp_error'):
                    self.busy=False;self.dashboard.conflict_busy=False;self.win._conflict_busy=False;self.start.configure(state='normal')
                    self.text.delete('1.0','end');self.text.insert('end',json.dumps(value,ensure_ascii=False,indent=2) if kind=='arp_result' else value)
                    self.status.set('ARP 清理操作已返回，请查看逐项结果；可重新检测，缓存也可能已自动重建。' if kind=='arp_result' else 'ARP 清理未确认/失败：'+value)
                    try:
                        directory=self.dashboard.file.parent/'arp-actions';directory.mkdir(parents=True,exist_ok=True)
                        record=dict(time=datetime.datetime.now().isoformat(),result=value)
                        (directory/(datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.json')).write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
                    except OSError as exc:self.text.insert('end','\n操作记录保存失败：'+str(exc))
                elif kind=='error':self.text.insert('end',value+'\n')
        except queue.Empty:pass
        self.timer=self.win.after(100,self.poll)

    def close(self):
        if self.busy:
            self.stop.set();messagebox.showinfo('正在停止','请等待当前网络操作完成后再关闭。',parent=self.win);return
        self.win.after_cancel(self.timer);self.win.destroy()
