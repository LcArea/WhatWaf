# encoding: utf8
import os
import sqlite3
import urlparse
import json
from lib.print_format import warning, info, prompt, fatal

from lib.settings import (
    EXPORTED_PAYLOADS_PATH,
    DATABASE_FILENAME,
    HOME,
    UNKNOWN_FIREWALL_NAME
)

from termcolor import colored
from lib.core.request import random_string


def initialize():
    """
    initialize the database and the HOME directory (~/.whatwaf)

    DATABASE_FILENAME 指向 ~/.whatwaf/whatwaf.sqlite
    如果不存在 whatwaf.sqlite 文件，就初始化
    """

    if not os.path.exists(DATABASE_FILENAME):
        # 如果没有 ~/.whatwaf HOME 文件夹, 就 mkdir 一个
        if not os.path.exists(HOME):
            try:
                os.makedirs(HOME)
            except:
                pass
    cursor = sqlite3.connect(DATABASE_FILENAME)
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS "cached_payloads" ('
        '`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,'
        '`payload` TEXT NOT NULL'
        ')'
    )
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS `cached_urls` ("
        "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "
        "`uri` TEXT NOT NULL, "
        "`working_tampers` TEXT NOT NULL DEFAULT 'N/A', "
        "`identified_protections` TEXT NOT NULL DEFAULT 'N/A',"
        "`identified_webserver`	TEXT NOT NULL DEFAULT 'N/A'"
        ")"
    )
    conn = sqlite3.connect(DATABASE_FILENAME, isolation_level=None, check_same_thread=False, timeout=10)
    return conn.cursor()


def fetch_data(cursor, table_name=None):
    """
    fetch all payloads out of the database

    :param cursor: default parameter
    :param table_name: get table data you want to in WhatWaf database
    :return: all of database data of table_name table
    """

    try:
        _ = cursor.execute("SELECT * FROM {}".format(table_name))
        data = _.fetchall()
    except:
        data = []
    return data


def display_cached(urls, payloads):
    """
    display the database information in a neat format

    其实就是将 cached_payload 和 cached_url 两个表的数据 全部展示， 把他们展示的漂亮点而已
    """
    if urls is not None:
        if len(urls) != 0:
            info("cached URLs:")
            # enumerate 是将一个可迭代的对象，例如列表或者元组， 加上一个序号索引（从0开始的）
            for i, cached in enumerate(urls):
                # i 为索引值, 从0开始的
                _, netlock, prots, tamps, server = cached
                print colored("{}".format("-" * 20), 'white')
                # 这段的意思是输出表格一样的东西，可视化url
                print(
                    "{sep} URL: {url}\n{sep} Identified Protections: {protect}\n"
                    "{sep} Working tampers: {tamp}\n{sep} Web server: {server}".format(
                        sep=colored("|", 'white'), url=netlock, protect=prots, tamp=tamps, server=server
                    )
                )
            print colored("{}".format("-" * 20), 'white')
        else:
            warning("there are no cached URLs in the database")

    if payloads is not None:
        if len(payloads) != 0:
            info("cached payloads:")
            print colored("{}".format("-" * 20), 'white')
            for i, payload in enumerate(payloads, start=1):
                print("{} {} {}".format(colored("#" + str(i), 'white'), colored("-->", 'white'), payload[-1]))
            print colored("{}".format("-" * 20), 'white')
        else:
            warning("no payloads have been cached into the database")


def insert_payload(payload, cursor):
    """
    insert a payload into the database

    :param payload: payload
    :param cursor: database cursor
    :return: Boolean
    """

    is_inserted = False
    try:
        current_cache = fetch_data(cursor, table_name="cached_payloads")
        # 保证写入最新的 paylaod id
        id_number = len(current_cache) + 1

        for item in current_cache:
            _, cache_payload = item
            if cache_payload == payload:
                is_inserted = True

        if not is_inserted:
            cursor.execute("INSERT INTO cached_payloads (id, payload) VALUES (?,?)", (id_number, payload))
    except Exception as e:
        return str(e)
    return True


def insert_url(cursor, netloc, working_tampers, identified_protections, webserver=None, return_found=False):
    """
    insert the URL into the database for future use, will only insert the netlock of the URL for easier
    caching and easier checking, so multiple netlocks of the same URL can hypothetically be used IE:
     - www.foo.bar
     - ftp.foo.bar
     - ssh.foo.bar

    :param cursor: 数据库指针
    :param netloc: 域名
    :param working_tampers: 产生作用的 tampers
    :param identified_protections: 识别出的 firewall 类型, 一般只有一个
    :param webserver: found_webserver 是检查是否 response 的 header 中有 server 字段
    :param return_found:
    :return:
    """

    try:
        is_inserted = False
        current_cache = fetch_data(cursor, table_name='cached_urls')
        id_number = len(current_cache) + 1

        if webserver is None:
            webserver = "N/A"

        for item in current_cache:
            # 如果 cached_url 表里面有 就返回这条记录
            _, cached_netloc, _, _, _ = item
            if str(cached_netloc).strip() == str(netloc).strip():
                if return_found:
                    return item
                else:
                    return False

        if not is_inserted:
            if len(identified_protections) > 1:
                # 不止识别一个 waf 指纹
                if UNKNOWN_FIREWALL_NAME in identified_protections:
                    identified_protections.remove(identified_protections.index(UNKNOWN_FIREWALL_NAME))

                # 不要用 , 来隔开
                # identified_protections = ",".join(identified_protections)
            else:
                try:
                    identified_protections = identified_protections[0]
                except:
                    identified_protections = "N/A"

            if len(working_tampers) > 1:
                working_tampers = ",".join(working_tampers)
            else:
                try:
                    working_tampers = working_tampers[0]
                except:
                    working_tampers = "N/A"

            # 这个好像是 sql 的预处理机制
            cursor.execute(
                "INSERT INTO cached_urls ("
                "id,uri,working_tampers,identified_protections,identified_webserver"
                ") VALUES (?,?,?,?,?)",
                (id_number, netloc, identified_protections, working_tampers, webserver)
            )
    except:
        return False
    return True


def check_url_cached(url, cursor):
    """
    check the netlock of the provided URL against the netlock of the
    cached URL

    :param url: url
    :param cursor: database cursor
    """
    is_cached = False
    cached_data = None

    # 获取所有 cached_url 表的数据
    cached_urls = fetch_data(cursor, table_name='cached_urls')
    # netloc是域名服务器, 这里 current_netloc_running 是获取域名,例如 www.baidu.com
    netloc = urlparse.urlparse(url).netloc

    for item in cached_urls:
        _, cached_netlock, _, _, _ = item
        # 如果 url 参数 给的 url 和 cached_url 数据库里的 url 有域名一致的情况, is_cached 就赋为 True
        # 如果遍历一遍还是没有, 那就是默认的 False 咯
        if str(cached_netlock) == str(netloc):
            is_cached = True
            cached_data = item

    # 如果数据库里有
    if is_cached:
        display_only = prompt(
            "this URL has already been ran, would you like to just display the cached data and skip",
            opts="yN",
            default="y"
        )
        if display_only.lower() == "y":
            return cached_data
        else:
            return None


def export_payloads(payloads, file_type):
    """
    export cached payloads from the database into a file for further use

    EXPORTED_PAYLOADS_PATH -> ~/.whatwaf/payload_exports

    payloads 是个列表, 列表里面嵌着每一列的元组

    return filename
    """

    if not os.path.exists(EXPORTED_PAYLOADS_PATH):
        os.makedirs(EXPORTED_PAYLOADS_PATH)

    # is_json = False
    # is_csv = False
    # is_yaml = False
    #
    # if file_type.lower() == "json":
    #     is_json = True
    # elif file_type.lower() == "csv":
    #     is_csv = True

    file_type = file_type.lower()

    if file_type == "yaml":
        try:
            import yaml
        except ImportError:
            fatal("you need the pyYAML library to export to yaml, get it by typing `pip install pyyaml`")
            exit(1)

    # random_string 返回一个 默认长度为5 的随机字符命令的文件，后缀为加上的 file_type 例如 csv json yalm
    # 如果都为 False， 就不已这些后缀结尾，直接返回一个 长度为 15 的随机字符
    filename = random_string(file_type=file_type, length=15)
    # file_path -> ~/.whatwaf/payload_export/whatwaf_文件类型_随机字符
    file_path = "{}/whatwaf_{}_export_{}".format(EXPORTED_PAYLOADS_PATH, file_type, filename)

    # 把数据库中的 payload列 的所有数据写入文件
    with open(file_path, "a+") as dump_file:
        if 'json' in file_type:
            retval = {"payloads": []}
            for item in payloads:
                # item 是每一行每一行的数据, item[-1] 是取列名为 payload 的数据, 其实就是取得列名为 payload 字段
                retval["payloads"].append(str(item[-1]))
            json.dump(retval, dump_file)

        elif 'csv' in file_type:
            import csv

            try:
                csv_data = [["payloads"], [str(p[-1]) for p in payloads]]
            except KeyError:
                pass
            writer = csv.writer(dump_file)
            writer.writerows(csv_data)
        elif 'yaml' in file_type:
            import yaml

            retval = {"payloads": []}
            for item in payloads:
                retval["payloads"].append(str(item[-1]))
            yaml.dump(retval, dump_file, default_flow_style=False)
        else:
            for item in payloads:
                dump_file.write("{}\n".format(str(item[-1])))

    return file_path
