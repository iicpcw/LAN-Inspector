"""In-app navigation; each tool is opened from the home screen."""
import tkinter as tk
from tkinter import ttk, messagebox


class Home:
    def __init__(self,root,inspect,scanner_factory,local_factory):
        self.root=root;self.inspect=inspect;self.scanner_factory=scanner_factory;self.local_factory=local_factory
        self.windows={}
        root.title('内网巡检台 2.4');root.geometry('980x650');root.minsize(820,560)
        frame=ttk.Frame(root,padding=38);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='内网巡检台',font=('Microsoft YaHei UI',26,'bold')).pack(anchor='w')
        ttk.Label(frame,text='选择要使用的功能',font=('Microsoft YaHei UI',13)).pack(anchor='w',pady=(8,24))
        for title,description,command in [
            ('动态拓扑','查看多网段设备图标、在线状态；编辑资产、保存布局和测试延时。',self.open_topology),
            ('网段扫描','主机发现、端口扫描、设备识别、MAC 厂商查询及报告导出。',self.open_scanner),
            ('本机端口管理','查看程序占用端口；勾选创建或撤销本机防火墙入站封堵规则。',self.open_local),
        ]:
            row=ttk.LabelFrame(frame,text=title,padding=16);row.pack(fill='x',pady=8)
            ttk.Label(row,text=description,wraplength=680).pack(side='left',fill='x',expand=True)
            ttk.Button(row,text='打开'+title,command=command,width=20).pack(side='right',padx=(12,0))
        ttk.Label(frame,text='功能窗口可独立切换；关闭功能窗口即可回到首页。资产与布局沿用原有文件。',wraplength=850).pack(anchor='w',pady=20)
        root.protocol('WM_DELETE_WINDOW',self.close)

    def existing(self,key):
        value=self.windows.get(key)
        if value:
            window,controller=value
            if window.winfo_exists():window.deiconify();window.lift();window.focus_force();return True
        return False

    def open_topology(self):
        if self.existing('topology'):return
        from dashboard import Dashboard
        window=tk.Toplevel(self.root)
        controller=Dashboard(window,self.inspect,advanced=self.open_scanner,local_ports=self.open_local)
        self.windows['topology']=(window,controller)

    def open_scanner(self):
        if self.existing('scanner'):return
        window=tk.Toplevel(self.root)
        controller=self.scanner_factory(window)
        self.windows['scanner']=(window,controller)

    def open_local(self):
        if self.existing('local'):return
        controller=self.local_factory(self.root)
        self.windows['local']=(controller.win,controller)

    def close(self):
        for window,controller in self.windows.values():
            if window.winfo_exists() and (getattr(controller,'busy',False) or getattr(controller,'running',False) or getattr(controller,'conflict_busy',False) or getattr(controller,'mac_busy',False)):
                window.lift()
                messagebox.showinfo('操作进行中','请先停止扫描并等待完成，或等待防火墙操作结束，再关闭程序。',parent=self.root)
                return
        topology=self.windows.get('topology')
        if topology and topology[0].winfo_exists():
            controller=topology[1]
            if controller.model.dirty and not controller.save():return
            controller.ping_stop.set()
        self.root.destroy()

