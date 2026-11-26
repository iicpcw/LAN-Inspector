"""Editable, persistent multi-subnet logical topology dashboard."""
import concurrent.futures as cf
import ipaddress
import json
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from inventory import Inventory, now
from app_paths import app_dir
from mac_sources import MacContext
from ip_conflict import normalize_mac
from device_icons import icon_kind, draw_icon
from network_tools import local_networks, reverse_name, latency
from mac_identity import mark_shared_mac, lookup

BASE=app_dir()


class Dashboard:
    def __init__(self,root,inspect,advanced=None,local_ports=None,startup=True,asset_file=None,auto_scan=True):
        self.root,self.inspect=root,inspect
        self.model=Inventory();self.file=Path(asset_file) if asset_file else BASE/'data'/'inventory.json'
        self.auto_scan=auto_scan
        self.events=queue.Queue();self.stop=threading.Event();self.ping_stop=threading.Event()
        self.running=False;self.pinging=False;self.conflict_busy=False;self.conflict_window=None;self.mac_busy=False;self.selected=None;self.zoom=1.0;self.drag=None;self.timer=None
        self.local_ips=set();self.adapters=[];self.detecting=False;self.view_networks=None
        root.title('内网巡检台 2.4 · 动态资产拓扑');root.geometry('1400x880');root.minsize(1000,660)
        outer=ttk.Frame(root,padding=12);outer.pack(fill='both',expand=True)
        ttk.Label(outer,text='动态资产拓扑',font=('Microsoft YaHei UI',20,'bold')).pack(anchor='w')
        ttk.Label(outer,text='点击图标查看详情，双击编辑。绿：已响应 / 灰：未确认 / 棕：仅 ARP / 红：端口告警 / 紫：MAC 异常。虚线仅表示网段归属。').pack(anchor='w',pady=5)
        bar=ttk.Frame(outer);bar.pack(fill='x',pady=6)
        self.target=tk.StringVar(value='');self.refresh=tk.BooleanVar(value=True);self.show_all=tk.BooleanVar(value=False)
        ttk.Label(bar,text='扫描网段').pack(side='left')
        ttk.Entry(bar,textvariable=self.target,width=48).pack(side='left',padx=6,fill='x',expand=True)
        self.scan_button=ttk.Button(bar,text='扫描 / 刷新',command=self.scan);self.scan_button.pack(side='left',padx=3)
        ttk.Button(bar,text='停止',command=self.stop_scan).pack(side='left',padx=3)
        ttk.Checkbutton(bar,text='完成后每 60 秒刷新',variable=self.refresh).pack(side='left',padx=8)
        adapter_bar=ttk.Frame(outer);adapter_bar.pack(fill='x',pady=3)
        ttk.Label(adapter_bar,text='本机网卡（可选择物理或虚拟网卡）').pack(side='left')
        self.adapter_choice=tk.StringVar(value='正在识别…')
        self.adapter_combo=ttk.Combobox(adapter_bar,textvariable=self.adapter_choice,state='readonly',width=100)
        self.adapter_combo.pack(side='left',fill='x',expand=True,padx=6)
        self.adapter_combo.bind('<<ComboboxSelected>>',self.choose_adapter)
        toolbar=ttk.Frame(outer);toolbar.pack(fill='x',pady=6)
        for label,command in [('添加设备',lambda:self.edit()),('编辑选中',lambda:self.edit(self.selected)),('删除选中',self.delete),('清除拓扑',self.clear_topology),('保存',self.save),('另存为',self.save_as),('打开资产文件',self.open_file),('自动布局',self.layout),('放大',lambda:self.scale(1.15)),('缩小',lambda:self.scale(1/1.15)),('测试选中设备延时',self.test_latency),('IP 冲突检测',self.open_conflicts),('补充选中 MAC',self.refresh_selected_mac)]:
            ttk.Button(toolbar,text=label,command=command).pack(side='left',padx=2)
        utility=ttk.Frame(outer);utility.pack(fill='x')
        ttk.Checkbutton(utility,text='显示全部已保存网段',variable=self.show_all,command=self.draw).pack(side='left',padx=2)
        ttk.Button(utility,text='打开 HTML 拓扑',command=self.open_browser_topology).pack(side='left',padx=2)
        if advanced:ttk.Button(utility,text='高级扫描 / HTML 报告',command=advanced).pack(side='left',padx=2)
        if local_ports:ttk.Button(utility,text='本机端口与防火墙',command=local_ports).pack(side='left',padx=2)
        ttk.Button(utility,text='重新识别本机网段',command=self.detect).pack(side='left',padx=2)
        self.progress=ttk.Progressbar(utility);self.progress.pack(side='left',fill='x',expand=True,padx=10)
        panes=ttk.Panedwindow(outer,orient='horizontal');panes.pack(fill='both',expand=True,pady=8)
        canvas_frame=ttk.Frame(panes);panes.add(canvas_frame,weight=4)
        self.canvas=tk.Canvas(canvas_frame,background='#edf2f8',highlightthickness=0)
        vs=ttk.Scrollbar(canvas_frame,orient='vertical',command=self.canvas.yview);vs.pack(side='right',fill='y')
        hs=ttk.Scrollbar(canvas_frame,orient='horizontal',command=self.canvas.xview);hs.pack(side='bottom',fill='x')
        self.canvas.configure(yscrollcommand=vs.set,xscrollcommand=hs.set);self.canvas.pack(fill='both',expand=True)
        side=ttk.Frame(panes);panes.add(side,weight=1)
        ttk.Label(side,text='设备详情 / 延时结果',font=('Microsoft YaHei UI',12,'bold')).pack(anchor='w')
        detail_frame=ttk.Frame(side);detail_frame.pack(fill='both',expand=True,pady=6)
        self.details=tk.Text(detail_frame,width=40,wrap='word')
        detail_scroll=ttk.Scrollbar(detail_frame,command=self.details.yview);detail_scroll.pack(side='right',fill='y')
        self.details.configure(yscrollcommand=detail_scroll.set);self.details.pack(fill='both',expand=True)
        self.details.insert('end','点击设备图标查看名称、类别、IP、MAC、在线状态及检查结果。\n\n双击编辑设备；拖动图标调整布局。')
        self.status=tk.StringVar(value='正在加载已保存资产…')
        ttk.Label(outer,textvariable=self.status,wraplength=1300).pack(anchor='w')
        self.canvas.bind('<ButtonPress-1>',self.press);self.canvas.bind('<B1-Motion>',self.motion);self.canvas.bind('<ButtonRelease-1>',self.release)
        self.canvas.bind('<Double-1>',lambda e:self.edit(self.selected) if self.selected else None)
        self.canvas.bind('<MouseWheel>',lambda e:self.canvas.yview_scroll(-1 if e.delta>0 else 1,'units'))
        self.canvas.bind('<Control-MouseWheel>',lambda e:self.scale(1.1 if e.delta>0 else 1/1.1))
        root.protocol('WM_DELETE_WINDOW',self.close)
        if startup:
            if self.file.exists():
                try:
                    self.model=Inventory.load(self.file)
                    self.target.set(self.model.target_text)
                    self.view_networks=self.parse_scope(self.model.target_text)
                except (OSError,ValueError,KeyError,TypeError) as exc:
                    messagebox.showerror('资产文件读取失败',str(exc)+'\n原文件不会覆盖，请另存新文件。')
                    self.file=BASE/'data'/'inventory-recovery.json'
            self.draw();self.detect_timer=self.root.after(150,self.detect)
        self.poll_timer=self.root.after(100,self.poll)

    @staticmethod
    def parse_scope(text):
        try:return list(dict.fromkeys(str(ipaddress.IPv4Network(t,strict=False)) for t in text.replace(',', ' ').split())) or None
        except ValueError:return None

    def visible_networks(self):
        return self.model.networks if self.show_all.get() or self.view_networks is None else self.view_networks

    def visible_group(self,asset,network,networks):
        if self.show_all.get() or self.view_networks is None:return asset['network']==network
        matches=[n for n in networks if ipaddress.IPv4Address(asset['ip']) in ipaddress.IPv4Network(n)]
        return bool(matches) and network==max(matches,key=lambda n:ipaddress.IPv4Network(n).prefixlen)

    def stop_scan(self):
        self.stop.set()
        if self.timer:self.root.after_cancel(self.timer);self.timer=None
        self.refresh.set(False)
        self.status.set('正在停止扫描，已关闭定时刷新。' if self.running else '已停止定时刷新。')

    def clear_topology(self):
        if self.running or self.conflict_busy or self.mac_busy or self.pinging or self.detecting:
            messagebox.showinfo('操作进行中','请先停止扫描并等待当前操作结束，再清除拓扑。');return
        if not messagebox.askyesno('清除全部拓扑','清除当前资产文件中的全部网段和设备（包括手工设备、备注及冲突记录）？\n程序会先保存可重新打开的备份；不会修改设备或防火墙。'):return
        import datetime
        backup=self.file.parent/(self.file.stem+'-backup-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.json')
        try:self.model.save(backup)
        except OSError as exc:messagebox.showerror('备份失败，未清除',str(exc));return
        previous=self.model;replacement=Inventory()
        replacement.target_text=self.target.get();replacement.dirty=True
        self.model=replacement
        if not self.save(quiet=True):self.model=previous;return
        self.stop_scan();self.selected=None;self.drag=None;self.view_networks=None;self.show_all.set(False)
        self.zoom=1.0;self.progress.configure(value=0);self.draw();self.show_details()
        self.canvas.xview_moveto(0);self.canvas.yview_moveto(0)
        self.status.set('拓扑已清空，定时刷新已停止。备份：'+str(backup)+'；填写网段后点击扫描。')

    def detect(self):
        if self.running or self.detecting or self.conflict_busy or self.mac_busy or self.pinging:return
        self.detecting=True
        self.status.set('正在识别本机网卡与网段…')
        def work():
            try:self.events.put(('adapters',local_networks()))
            except Exception as exc:self.events.put(('error',str(exc)))
        threading.Thread(target=work,daemon=True).start()

    def choose_adapter(self,event=None):
        index=self.adapter_combo.current()
        if 0<=index<len(self.adapters):
            self.target.set(self.adapters[index]['network'])
            self.status.set('已选择网卡 '+self.adapters[index]['name']+'；点击“扫描 / 刷新”检测该网段。当前轮扫描的范围不会中途改变。')

    def accept_adapters(self,adapters):
        self.detecting=False
        self.adapters=adapters;self.local_ips={r['ip'] for r in adapters}
        self.adapter_combo.configure(values=[r['name']+' | '+r['ip']+' | '+r['network']+' | 网关 '+(','.join(r.get('gateways',[])) or '未配置') for r in adapters])
        current=next((i for i,r in enumerate(adapters) if r['network'] in self.target.get().replace(',',' ').split()),None)
        if adapters:self.adapter_combo.current(current if current is not None else 0)
        else:self.adapter_choice.set('未识别到活动 IPv4 网卡，可手动填写目标网段')
        for a in self.model.assets.values():a['gateway_current']=False
        for row in adapters:
            if row['network'] not in self.model.networks:self.model.networks.append(row['network'])
            asset=self.model.find(row['ip']) or self.model.add(row['ip'],name='本机 · '+row['name'],category='本机 Windows',network=row['network'])
            self.model.observe(dict(ip=row['ip'],status='在线',mac=normalize_mac(row.get('mac','')),device_type='本机 Windows',evidence='本机活动网卡',ports='',os_family='Windows（本机）',os_confidence='高',mac_source='本机网卡配置',mac_interface=row['name']+' | '+row['ip'],mac_state='本机读取',mac_confidence='高（本机读取）',**lookup(normalize_mac(row.get('mac','')))))
        for row in adapters:
            for gateway in row.get('gateways',[]):
                try:self.model.record_gateway(gateway,dict(adapter=row['name'],local_ip=row['ip'],source='本机网卡配置，不代表已探测在线'),row['network'])
                except ValueError:continue
        if not self.target.get() and adapters:self.target.set(adapters[0]['network'])
        self.draw();self.save(quiet=True)
        if self.target.get() and self.auto_scan:self.scan()
        elif self.target.get():self.status.set('网卡识别完成，已暂停自动扫描，可进行 ARP 缓存操作。')
        else:self.status.set('未识别到活动 IPv4 网卡，请填写完整目标网段，例如 192.168.4.0/24。')

    def scan(self):
        if self.running or self.conflict_busy or self.mac_busy or self.pinging or self.detecting:return
        if self.timer:self.root.after_cancel(self.timer);self.timer=None
        try:addresses=self.model.add_networks(self.target.get())
        except ValueError as exc:
            messagebox.showerror('网段无效',str(exc)+'\n例如：192.168.192.0/24 或 192.168.4.0/24。大网段请分批。');return
        self.view_networks=self.parse_scope(self.target.get());self.show_all.set(False)
        self.selected=None;self.show_details()
        self.canvas.xview_moveto(0);self.canvas.yview_moveto(0)
        self.stop.clear();self.running=True;self.root._topology_busy=True
        self.scan_button.configure(state='disabled');self.progress.configure(maximum=len(addresses),value=0)
        context=MacContext(self.adapters,self.adapters[self.adapter_combo.current()]['ip'] if 0<=self.adapter_combo.current()<len(self.adapters) else None)
        self.scan_error=False
        self.processed=0;self.scan_targets=list(addresses);self.new_found=0
        for a in self.model.assets.values():
            if a['ip'] in addresses and a['observation']:a['observation']['stale']=True
        self.status.set('扫描中：{} 个地址；已有资产不会因未响应而删除。'.format(len(addresses)));self.draw()
        def probe(ip):
            row=self.inspect(ip,[22,80,135,139,443,445,3389,5985,5986,8000,8080,8443],.5,self.stop,True,resolve_mac=False)
            if row:
                ports={int(x) for x in row.get('ports','').split(',') if x}
                row=context.enrich(row,self.stop,netbios=bool(ports & {139,445}) or 'Windows' in row.get('os_family',''))
                if row['status']=='在线' and not self.stop.is_set():row['hostname']=reverse_name(row['ip'])
            return row
        def work():
            try:
                context.refresh();collected=[]
                with cf.ThreadPoolExecutor(max_workers=32) as pool:
                    jobs={pool.submit(probe,ip):ip for ip in addresses}
                    for future in cf.as_completed(jobs):
                        row=future.result()
                        if row:
                            collected.append(row)
                            self.events.put(('row',row))
                missing=[r for r in collected if not r.get('mac')]
                if missing and not self.stop.is_set():
                    context.refresh()
                    self.events.put(('mac_updates',[context.enrich(r,self.stop,active=False) for r in missing]))
            except Exception as exc:self.events.put(('error',str(exc)))
            finally:self.events.put(('done',None))
        threading.Thread(target=work,daemon=True).start()

    def draw(self):
        self.canvas.delete('all');z=self.zoom
        y=30
        networks=self.visible_networks()
        for network in networks:
            group=[a for a in self.model.assets.values() if self.visible_group(a,network,networks)]
            self.canvas.create_rectangle(25*z,y*z,1230*z,(y+42)*z,fill='#243b64',outline='',tags=('background',))
            self.canvas.create_text(45*z,(y+21)*z,text=network+' · '+str(len(group))+' 台资产（逻辑归属）',anchor='w',fill='white',font=('Microsoft YaHei UI',max(8,int(12*z))))
            hub=(620,y+42);start=y+80
            occupied=[]
            slot=0
            for a in sorted(group,key=lambda a:(a.get('x') is None,ipaddress.ip_address(a['ip']))):
                x,cy=a.get('x'),a.get('y')
                while x is None or cy is None or cy<start or any(abs(x-old_x)<280 and abs(cy-old_y)<180 for old_x,old_y in occupied):
                    if self.drag and self.selected==a['id'] and x is not None and cy is not None:break
                    x,cy=35+(slot%4)*300,start+(slot//4)*190
                    slot+=1
                occupied.append((x,cy))
                a['x'],a['y']=x,cy
                x,cy=a['x'],a['y'];d=self.model.displayed(a);tag='asset:'+a['id']
                color='#238571' if d['status']=='在线' else '#8c9aad'
                if '手工' in d['status']:color='#697386'
                elif d['status']=='仅 ARP 响应':color='#aa7629'
                if a['observation'].get('risk_ports'):color='#b42318'
                if a.get('conflict_alert'):color='#9c2780'
                self.canvas.create_line(hub[0]*z,hub[1]*z,(x+138)*z,cy*z,fill='#a2afc2',dash=(4,5),tags=('edge',))
                self.canvas.create_oval((x+80)*z,(cy+2)*z,(x+198)*z,(cy+114)*z,fill='#e1edff' if self.selected==a['id'] else 'white',outline='#1565c0' if self.selected==a['id'] else (color if a.get('conflict_alert') or a['observation'].get('risk_ports') else '#dae3ef'),width=3 if self.selected==a['id'] else 1,tags=(tag,))
                kind=icon_kind(d['category'])
                draw_icon(self.canvas,kind,(x+98)*z,(cy+18)*z,z*1.15,color,tags=(tag,))
                self.canvas.create_oval((x+181)*z,(cy+9)*z,(x+195)*z,(cy+23)*z,fill=color,outline='',tags=(tag,))
                if a.get('conflict_alert'):self.canvas.create_text((x+188)*z,(cy+16)*z,text='!',fill='white',tags=(tag,))
                for j,line in enumerate([d['name'],a['ip']] if d['name']!=a['ip'] else [a['ip']]):
                    text=str(line);text=text[:24]+('…' if len(text)>24 else '')
                    self.canvas.create_text((x+139)*z,(cy+133+j*23)*z,text=text,anchor='center',fill=color if j==2 else '#243b64',font=('Microsoft YaHei UI',max(4,int((11 if j==0 else 10)*z))),tags=(tag,))
            last=max([a['y']+185 for a in group]+[start+50]);y=max(y+160,last+25)
        if not networks:self.canvas.create_text(30,35,anchor='nw',text='识别本机网段后将显示设备；也可手动填写跨网段目标或添加设备。',fill='#243b64')
        self.canvas.tag_lower('edge')
        bbox=self.canvas.bbox('all');self.canvas.configure(scrollregion=(0,0,max(1300*z,bbox[2]+30 if bbox else 1300),max(800*z,bbox[3]+30 if bbox else 800)))

        if getattr(self,'browser_topology',None):
            try:self.browser_topology.update(self)
            except OSError as exc:self.status.set('HTML 拓扑同步失败：'+str(exc))

    def open_browser_topology(self):
        from browser_topology import BrowserTopology
        try:
            if not getattr(self,'browser_topology',None):self.browser_topology=BrowserTopology()
            self.browser_topology.update(self)
            self.browser_topology.open()
        except OSError as exc:messagebox.showerror('HTML 拓扑打开失败',str(exc))

    def press(self,event):
        px,py=self.canvas.canvasx(event.x),self.canvas.canvasy(event.y)
        hits=self.canvas.find_overlapping(px,py,px,py)
        tags=next((self.canvas.gettags(item) for item in reversed(hits) if any(t.startswith('asset:') for t in self.canvas.gettags(item))),())
        asset=next((t[6:] for t in tags if t.startswith('asset:')),None)
        if asset:
            self.selected=asset;self.drag=(self.canvas.canvasx(event.x)/self.zoom,self.canvas.canvasy(event.y)/self.zoom)
            self.show_details();self.draw()

    def motion(self,event):
        if not self.drag or not self.selected:return
        x,y=self.canvas.canvasx(event.x)/self.zoom,self.canvas.canvasy(event.y)/self.zoom
        a=self.model.assets[self.selected];a['x']=max(0,a['x']+x-self.drag[0]);a['y']=max(0,a['y']+y-self.drag[1])
        self.drag=(x,y);self.model.dirty=True;self.draw()

    def release(self,event):
        if self.drag:self.drag=None;self.draw();self.save(quiet=True)

    def scale(self,factor):
        self.zoom=max(.65,min(2.0,self.zoom*factor));self.draw()

    def layout(self):
        for a in self.model.assets.values():a['x']=a['y']=None
        self.model.dirty=True;self.draw();self.save(quiet=True)

    def show_details(self,extra=''):
        self.details.delete('1.0','end')
        if self.selected in self.model.assets:
            a=self.model.assets[self.selected];d=self.model.displayed(a)
            self.details.insert('end','\n'.join(k+'：'+str(v) for k,v in [('名称',d['name']),('类别',d['category']),('服务标识厂商',a['observation'].get('device_vendor','未知')),('MAC 注册厂商',a['observation'].get('mac_vendor','未知')),('产品线索',a['observation'].get('model_hint','未知')),('软件平台线索',a['observation'].get('platform_hint','未知')),('OS',d['os_family']),('OS 置信度','手工指定' if a.get('os_override') else a['observation'].get('os_confidence','未知')),('IP',a['ip']),('MAC',d['mac']),('状态',d['status']),('网段',a['network']),('备注',a['note']),('最近在线',a['last_seen']),('最近检查',a['last_check'])]))
            if a.get('conflict_last_check'):
                self.details.insert('end','\n\nIP 冲突检测：'+json.dumps(dict(alert=a.get('conflict_alert'),latest=a.get('conflict_last_check'),events=a.get('conflict_events'),mac_observations=a.get('mac_observations')),ensure_ascii=False,indent=2))
            if a.get('gateway_sources'):
                self.details.insert('end','\n\n网关来源：'+json.dumps(a['gateway_sources'],ensure_ascii=False,indent=2)+'\n当前网卡配置：'+str(bool(a.get('gateway_current')))+'\n网关角色不等于路由器硬件类型；配置存在不代表已确认在线。')
            self.details.insert('end','\n\n观测信息（与手工字段分开保存）：\n'+json.dumps(a['observation'],ensure_ascii=False,indent=2))
        if self.selected not in self.model.assets:self.details.insert('end','点击设备图标查看详情。\n双击编辑，拖动调整布局。')
        if extra:self.details.insert('end','\n\n'+extra)

    def edit(self,identity=None):
        if self.running or self.conflict_busy or self.mac_busy or self.pinging or self.detecting:
            messagebox.showinfo('正在扫描','请等待扫描完成，或停止后编辑设备。');return
        a=self.model.assets.get(identity) if identity else None
        if identity and not a:return
        dialog=tk.Toplevel(self.root);dialog.title('编辑设备' if a else '添加设备');dialog.transient(self.root);dialog.grab_set()
        fields={}
        for i,(key,label,default) in enumerate([('ip','完整 IPv4 地址',''),('name','名称（留空使用 DNS/IP）',''),('category','类别（留空使用识别结果）',''),('os_override','OS（留空使用识别结果）',''),('mac','MAC（可留空）',''),('network','所属完整 CIDR 网段',self.target.get().split()[0] if self.target.get().split() else ''),('note','备注','')]):
            ttk.Label(dialog,text=label).grid(row=i,column=0,padx=10,pady=7,sticky='w')
            fields[key]=tk.StringVar(value=a.get(key,default) if a else default)
            if key=='category':
                ttk.Combobox(dialog,textvariable=fields[key],width=46,values=['','电脑','Windows 终端','Linux 终端','手机','iOS/iPadOS 手机','Android 手机','平板','服务器','交换机','路由器','防火墙','打印机','未知设备']).grid(row=i,column=1,padx=10)
            elif key=='os_override':
                ttk.Combobox(dialog,textvariable=fields[key],width=46,values=['','Windows','Linux','macOS','iOS/iPadOS','Android','RouterOS','未知']).grid(row=i,column=1,padx=10)
            else:
                ttk.Entry(dialog,textvariable=fields[key],width=48).grid(row=i,column=1,padx=10)
        state=tk.StringVar(value=a.get('manual_state','自动') if a else '自动')
        ttk.Label(dialog,text='状态来源').grid(row=7,column=0,padx=10,sticky='w')
        ttk.Combobox(dialog,textvariable=state,values=['自动','离线（手工）','停用（手工）'],state='readonly').grid(row=7,column=1,pady=8)
        def commit():
            try:
                values={k:v.get().strip() for k,v in fields.items()};parsed=ipaddress.IPv4Address(values['ip'])
                net=ipaddress.ip_network(values['network'],strict=False) if values['network'] else ipaddress.ip_network(str(parsed)+'/32')
                if parsed not in net:raise ValueError('设备 IP 不属于所填网段')
                if values['mac']:
                    import re
                    if not re.fullmatch(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',values['mac']):raise ValueError('MAC 请使用 AA:BB:CC:DD:EE:FF 格式')
                duplicate=self.model.find(str(parsed))
                if duplicate and duplicate is not a:raise ValueError('该 IP 已存在')
                values['ip']=str(parsed);values['network']=str(net)
                if a:
                    if values['ip']!=a['ip']:a['observation']={};a['last_check']=a['last_seen']=''
                    if values['network']!=a['network']:a['x']=a['y']=None
                    a.update(values,manual_state=state.get());self.model.dirty=True
                    if str(net) not in self.model.networks:self.model.networks.append(str(net))
                else:self.selected=self.model.add(**values,manual_state=state.get())['id']
                self.draw();self.show_details();self.save(quiet=True);dialog.destroy()
            except ValueError as exc:messagebox.showerror('输入无效',str(exc),parent=dialog)
        ttk.Button(dialog,text='保存设备',command=commit).grid(row=8,column=1,pady=12)

    def delete(self):
        if self.running or self.conflict_busy or self.mac_busy or self.pinging or self.detecting or self.selected not in self.model.assets:return
        if messagebox.askyesno('删除资产','从资产图删除所选设备？再次扫描发现它时会重新添加。'):
            del self.model.assets[self.selected];self.selected=None;self.model.dirty=True;self.draw();self.show_details();self.save(quiet=True)

    def save(self,quiet=False):
        try:self.model.save(self.file)
        except OSError as exc:messagebox.showerror('保存失败',str(exc));return False
        if not quiet:self.status.set('已保存：'+str(self.file))
        return True

    def save_as(self):
        if self.running or self.conflict_busy or self.mac_busy or self.pinging or self.detecting:return
        path=filedialog.asksaveasfilename(defaultextension='.json',filetypes=[('资产文件','*.json')])
        if path:
            previous=self.file;self.file=Path(path)
            if not self.save():self.file=previous

    def open_file(self):
        if self.running or self.conflict_busy or self.mac_busy or self.pinging or self.detecting:return
        if self.model.dirty and not self.save():return
        path=filedialog.askopenfilename(filetypes=[('资产文件','*.json')])
        if not path:return
        try:loaded=Inventory.load(path)
        except (OSError,ValueError,KeyError,TypeError) as exc:messagebox.showerror('读取失败',str(exc));return
        self.model=loaded;self.file=Path(path);self.target.set(loaded.target_text);self.view_networks=self.parse_scope(loaded.target_text);self.show_all.set(False);self.selected=None;self.draw();self.show_details()
        if self.timer:self.root.after_cancel(self.timer);self.timer=None
        self.status.set('资产已载入；历史在线记录待刷新。扫描输入可填写任意可达网段。')

    def refresh_selected_mac(self):
        if self.running or self.conflict_busy or self.mac_busy or self.pinging or self.detecting:return
        if self.selected not in self.model.assets:
            messagebox.showinfo('补充 MAC','请先单击选中一个设备。');return
        identity=self.selected;asset=self.model.assets[identity];ip=asset['ip']
        adapter=self.adapters[self.adapter_combo.current()] if 0<=self.adapter_combo.current()<len(self.adapters) else None
        self.mac_busy=True;self.root._mac_busy=True;self.status.set('正在多来源获取 '+ip+' 的 MAC…')
        base=dict(asset.get('observation') or dict(ip=ip,status='未确认',ports=''),ip=ip)
        def work():
            try:
                context=MacContext(preferred_source=adapter['ip'] if adapter else None);context.refresh()
                result=context.enrich(base,self.stop,netbios=True)
                if not result.get('mac') and not self.stop.is_set():
                    context.refresh();result=context.enrich(result,self.stop,active=False)
                self.events.put(('selected_mac',(identity,result)))
            except Exception as exc:self.events.put(('mac_error',str(exc)))
        self.stop.clear();threading.Thread(target=work,daemon=True).start()

    def open_conflicts(self):
        if self.conflict_window and self.conflict_window.win.winfo_exists():
            self.conflict_window.win.lift();return
        from conflict_window import ConflictWindow
        from lan_inspector import mac
        self.conflict_window=ConflictWindow(self,mac)

    def test_latency(self):
        if self.pinging or self.running or self.mac_busy or self.conflict_busy or self.detecting:return
        if self.selected not in self.model.assets:messagebox.showinfo('测试延时','请先单击选择设备');return
        identity=self.selected;ip=self.model.assets[identity]['ip'];self.pinging=True;self.ping_stop.clear();self.status.set('正在测试到 '+ip+' 的 ICMP 延时（4 次）…')
        def work():
            try:self.events.put(('latency',(identity,latency(ip,self.ping_stop))))
            except Exception as exc:self.events.put(('error',str(exc)));self.events.put(('latency_done',None))
        threading.Thread(target=work,daemon=True).start()

    def poll(self):
        redraw=False
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='adapters':self.accept_adapters(value)
                elif kind=='row':
                    self.processed+=1
                    if value['ip'] in self.local_ips:
                        value=dict(value,status='在线',os_family='Windows（本机）',os_confidence='高',evidence='本机活动网卡；'+value.get('evidence',''))
                    asset=self.model.observe(value)
                    if asset:
                        obs=[a['observation'] for a in self.model.assets.values() if a['observation']]
                        for row in mark_shared_mac(obs,value.get('mac')):pass
                    self.progress.configure(value=self.processed);redraw=True
                    self.status.set('扫描中：{}/{}；资产 {} 台'.format(self.processed,len(self.scan_targets),len(self.model.assets)))
                elif kind=='mac_updates':
                    for updated in value:
                        asset=self.model.find(updated['ip'])
                        if asset:asset['observation']=updated;self.model.dirty=True
                        else:self.model.observe(updated)
                    for updated in value:mark_shared_mac([a['observation'] for a in self.model.assets.values() if a['observation']],updated.get('mac'))
                    redraw=True
                elif kind=='selected_mac':
                    identity,row=value;self.mac_busy=False;self.root._mac_busy=False
                    if identity in self.model.assets and self.model.assets[identity]['ip']==row['ip']:
                        asset=self.model.assets[identity];asset['observation']=row;self.model.dirty=True
                        mark_shared_mac([a['observation'] for a in self.model.assets.values() if a['observation']],row.get('mac'));self.save(quiet=True)
                    self.status.set(row['ip']+'：'+(row.get('mac') or '未获取')+'；'+row.get('mac_source','')+'；'+row.get('mac_note',''));redraw=True
                elif kind=='mac_error':
                    self.mac_busy=False;self.root._mac_busy=False;self.status.set('MAC 获取失败：'+value)
                elif kind=='done':
                    self.running=False;self.root._topology_busy=False;self.scan_button.configure(state='normal');self.draw();self.save(quiet=True);redraw=True
                    self.status.set(('已停止' if self.stop.is_set() else ('扫描部分失败' if self.scan_error else '扫描完成'))+'；资产 {} 台；已保留手工设备及未响应历史设备。'.format(len(self.model.assets)))
                    if self.refresh.get() and not self.stop.is_set() and not self.scan_error:self.timer=self.root.after(60000,lambda:self.scan() if self.refresh.get() else None)
                elif kind=='latency':
                    identity,result=value;self.pinging=False
                    if identity in self.model.assets and self.model.assets[identity]['ip']==result['ip']:
                        a=self.model.assets[identity];a['observation']['latency']=result
                        if result['received']:
                            obs=dict(a['observation'],ip=a['ip'],status='在线',stale=False);self.model.observe(obs)
                        self.model.dirty=True;self.save(quiet=True)
                        if self.selected==identity:self.show_details('延时结果：\n'+json.dumps(result,ensure_ascii=False,indent=2))
                    self.status.set('{}：收包 {}/{}，丢包 {}%，最小/平均/最大 {} / {} / {} ms'.format(result['ip'],result['received'],result['sent'],result['loss'],result['minimum'],result['average'],result['maximum']));redraw=True
                elif kind=='latency_done':self.pinging=False
                elif kind=='error':
                    self.detecting=False
                    if self.running:self.scan_error=True
                    self.status.set('提示：'+value)
        except queue.Empty:pass
        if redraw:self.draw();self.show_details()
        self.poll_timer=self.root.after(100,self.poll)

    def close(self):
        def busy(window):
            return getattr(window,'_local_ports_busy',False) or getattr(window,'_conflict_busy',False) or getattr(window,'_mac_busy',False) or any(busy(child) for child in window.winfo_children())
        if busy(self.root):
            messagebox.showinfo('操作进行中','请等待端口、IP 冲突或 MAC 获取操作完成后退出。');return
        if self.detecting or self.pinging:
            self.ping_stop.set();messagebox.showinfo('操作进行中','请等待网卡识别或延时测试结束后退出。');return
        if self.running:
            self.stop_scan();messagebox.showinfo('正在停止','正在停止扫描，请等待当前探测结束后再次关闭。');return
        if self.model.dirty and not self.save():return
        self.ping_stop.set()
        for callback in (getattr(self,'poll_timer',None),getattr(self,'detect_timer',None),self.timer):
            if callback:
                try:self.root.after_cancel(callback)
                except tk.TclError:pass
        self.root.destroy()


