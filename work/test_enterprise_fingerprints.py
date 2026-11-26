import sys,unittest
sys.path.insert(0,'outputs/LAN-Inspector')
from fingerprint_engine import analyze
from device_icons import icon_kind

def title(text,server='nginx'):
    return analyze([80],{'80':'HTTP/1.1 200 OK\r\nServer: '+server+'\r\n\r\n<title>'+text+'</title>'})
class Tests(unittest.TestCase):
    def test_huawei_roles(self):
        for name,kind in [('Huawei AR6120','路由器'),('Huawei CloudEngine S5735-L','交换机'),('Huawei USG6650','防火墙')]:
            r=title(name);self.assertEqual(r['device_type'],kind);self.assertEqual(r['device_vendor'],'华为');self.assertEqual(r['os_family'],'未知')
    def test_h3c_roles(self):
        for name,kind in [('H3C MSR-810','路由器'),('H3C S5560X-30C','交换机'),('H3C SecPath F1000-AK','防火墙')]:
            r=title(name);self.assertEqual(r['device_type'],kind);self.assertEqual(r['device_vendor'],'华三 H3C')
    def test_zte_router_not_all_zxr10(self):
        for name,kind in [('ZTE ZXR10 M6000-S','路由器'),('ZTE ZXR10 ZSR V2','路由器'),('ZTE ZXR10 9900','交换机'),('ZTE ZXR10 5960X','交换机')]:
            r=title(name);self.assertEqual(r['device_type'],kind);self.assertEqual(r['device_vendor'],'中兴 ZTE')
        self.assertEqual(title('ZTE ZXR10')['device_type'],'未知设备')
    def test_sangfor_security_products(self):
        for name,kind in [('Sangfor NGAF','防火墙'),('SANGFOR_NGAF_V8.0.6','防火墙'),('深信服 AF-1000-FH','防火墙'),('深信服上网行为管理','上网行为管理设备'),('Sangfor EasyConnect SSL VPN','VPN 网关'),('Sangfor aTrust','零信任访问网关')]:
            r=title(name);self.assertEqual(r['device_type'],kind);self.assertEqual(r['device_vendor'],'深信服');self.assertNotEqual(icon_kind(kind),'router')
    def test_brand_alone_is_not_role(self):
        for name in ('Huawei','H3C Web Administration','ZTE Login','Sangfor Login'):
            self.assertEqual(title(name)['device_type'],'未知设备')
    def test_vrp_comware_not_router_by_default(self):
        for banner,os_name in [('SSH-2.0-Huawei-VRP','VRP'),('SSH-2.0-H3C-Comware-7.1','Comware')]:
            r=analyze([22],{'22':banner});self.assertEqual(r['os_family'],os_name);self.assertEqual(r['device_type'],'网络设备（具体类型未知）')
    def test_title_platform_is_not_confirmed_os(self):
        r=title('H3C Comware Web');self.assertEqual(r['platform_hint'],'Comware');self.assertEqual(r['os_family'],'未知')
    def test_body_and_documentation_not_fingerprints(self):
        self.assertEqual(title('H3C MSR610 Documentation')['device_vendor'],'未知')
        r=analyze([80],{'80':'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<title>Login</title>Huawei AR6120 H3C MSR810 Sangfor NGAF'})
        self.assertEqual(r['device_vendor'],'未知');self.assertEqual(r['device_type'],'未知设备')
    def test_separate_vendor_conflict(self):
        r=analyze([80,443],{'80':'Huawei','443':'H3C'})
        self.assertEqual(r['vendor_confidence'],'低');self.assertEqual(r['device_type'],'未知设备')
    def test_header_brand_can_qualify_model_title(self):
        r=title('S5560X','H3CWebServer')
        self.assertEqual(r['device_vendor'],'华三 H3C');self.assertEqual(r['device_type'],'交换机')
unittest.main()
