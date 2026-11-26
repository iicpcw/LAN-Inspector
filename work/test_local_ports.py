import sys,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
sys.path.insert(0,'outputs/LAN-Inspector')
import local_ports as m
class Tests(unittest.TestCase):
    def test_deduplicate_protocol_port(self):
        rows=[{'protocol':'TCP','port':80},{'protocol':'TCP','port':80},{'protocol':'UDP','port':80}]
        self.assertEqual(len(m.validate_requests(rows)),2)
    def test_reject_input(self):
        for row in [dict(protocol='TCP;whoami',port=80),dict(protocol='TCP',port='80;whoami'),dict(protocol='TCP',port=0),dict(protocol='UDP',port=65536),dict(protocol='TCP',port=True)]:
            with self.assertRaises(ValueError):m.validate_requests([row])
    def test_nonadmin_no_mutation(self):
        with patch.object(m.platform,'system',return_value='Windows'),patch.object(m,'is_admin',return_value=False),patch.object(m.subprocess,'run') as run:
            with self.assertRaises(PermissionError):m.run_action('block',[dict(protocol='TCP',port=80)])
            run.assert_not_called()
    def test_no_selection_no_mutation(self):
        with patch.object(m.platform,'system',return_value='Windows'),patch.object(m.subprocess,'run') as run:
            with self.assertRaises(ValueError):m.run_action('remove',[])
            run.assert_not_called()
    def test_structured_args(self):
        response=dict(ok=True,data=dict(endpoints=[],rules=[],profiles=[],warnings=[]),results=[])
        fake=MagicMock(stdout=json.dumps(response).encode(),stderr=b'',returncode=0)
        with patch.object(m.platform,'system',return_value='Windows'),patch.object(m,'is_admin',return_value=True),patch.object(m.subprocess,'run',return_value=fake) as run:
            self.assertEqual(m.run_action('block',[dict(protocol='TCP',port=80)]),response)
            args=run.call_args[0][0]
            self.assertIn('-File',args)
            self.assertNotIn('-Command',args)
            self.assertNotIn('shell',run.call_args[1])
            import base64
            decoded=json.loads(base64.b64decode(args[-1]))
            self.assertEqual(decoded,[dict(protocol='TCP',port=80)])
    def test_timeout_unknown(self):
        with patch.object(m.platform,'system',return_value='Windows'),patch.object(m,'is_admin',return_value=True),patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('test',180)):
            with self.assertRaisesRegex(RuntimeError,'结果未确认'):m.run_action('block',[dict(protocol='TCP',port=80)])
    def test_script_error(self):
        fake=MagicMock(stdout=b'{"ok":false,"error":"Denied"}',stderr=b'',returncode=1)
        with patch.object(m.platform,'system',return_value='Windows'),patch.object(m.subprocess,'run',return_value=fake):
            with self.assertRaisesRegex(RuntimeError,'Denied'):m.run_action('scan')
    def test_ui_selection_and_remove_scope(self):
        root=m.tk.Tk();root.withdraw();ui=m.LocalPortWindow(root)
        endpoint=dict(protocol='TCP',port=80,address='0.0.0.0',pid=10,process='test',state='TCP listening')
        rule=dict(name='LANInspector.LocalPortBlock.v1.TCP.80',protocol='TCP',port='80',enabled='True',activeStore=True,direction='Inbound',action='Block',profile='Any')
        unrelated=dict(rule,name='Other.Firewall.Rule')
        ui.render(dict(endpoints=[endpoint,dict(endpoint,address='::')],rules=[rule,unrelated],profiles=[],warnings=[]))
        self.assertEqual(len(ui.rules),1)
        ui.select_all()
        self.assertEqual(len(ui.checked_endpoints),2)
        with patch.object(m,'is_admin',return_value=True),patch.object(m.messagebox,'askyesno',return_value=True),patch.object(ui,'submit') as submit:
            ui.mutate('block')
            submit.assert_called_once_with('block',[dict(protocol='TCP',port=80)])
        ui.flip('r0',True)
        with patch.object(m,'is_admin',return_value=True),patch.object(m.messagebox,'askyesno',return_value=True),patch.object(ui,'submit') as submit:
            ui.mutate('remove')
            submit.assert_called_once_with('remove',[dict(protocol='TCP',port=80)])
        root.destroy()
    def test_cancel_no_apply(self):
        root=m.tk.Tk();root.withdraw();ui=m.LocalPortWindow(root)
        ui.endpoints={'e0':dict(protocol='TCP',port=3389)};ui.checked_endpoints={'e0'}
        with patch.object(m,'is_admin',return_value=True),patch.object(m.messagebox,'askyesno',return_value=False),patch.object(ui,'submit') as submit:
            ui.mutate('block');submit.assert_not_called()
        root.destroy()
    def test_busy_close(self):
        root=m.tk.Tk();root.withdraw();ui=m.LocalPortWindow(root);ui.busy=True
        with patch.object(m.messagebox,'showinfo') as info:
            ui.close();info.assert_called_once();self.assertTrue(ui.win.winfo_exists())
        root.destroy()
unittest.main()
