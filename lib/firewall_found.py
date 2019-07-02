# encoding: utf8
import re
import sys
import json
import hashlib
import base64
try:
    from urllib2 import Request, urlopen
except ImportError:
    from urllib.request import Request, urlopen

import requests
from bs4 import BeautifulSoup

import lib.settings
import lib.print_format


def create_identifier(data):
    obj = hashlib.sha1()
    try:
        obj.update(data)
    except:
        obj.update(data.encode("utf-8"))
    return obj.hexdigest()[1:10]


def get_token(path):
    """
    TOKEN_PATH="{}/content/data/auth.key".format(CUR_DIR)

    we know what this is for
    """
    with open(path) as _token:
        data = _token.read()
        token, n = data.split(":")
        for _ in range(int(n)):
            token = base64.b64decode(token)
    return token


def ensure_no_issue(param):
    """
    ensure that there is not already an issue that has been created for yours

    :param param: 10 位的 sha1 hash
    :return:
    """

    urls = (
        "https://github.com/Ekultek/WhatWaf/issues",
        "https://github.com/Ekultek/WhatWaf/issues?q=is%3Aissue+is%3Aclosed"
    )
    for url in urls:
        req = requests.get(url)
        param = re.compile(param)
        try:
            # 从已知的问题中找到了 就返回 true
            if param.search(req.content) is not None:
                return True
        except:
            content = str(req.content)
            if param.search(content) is not None:
                return True
    # 如果都没有找到, 就返回 False
    return False


def find_url(params):
    """
    get the URL that your issue is created at
    """
    searches = (
        "https://github.com/Ekultek/WhatWaf/issues",
        "https://github.com/Ekultek/WhatWaf/issues?q=is%3Aissue+is%3Aclosed"
    )
    for search in searches:
        retval = "https://github.com{}"
        href = None
        searcher = re.compile(params, re.I)
        req = requests.get(search)
        status, html = req.status_code, req.content
        if status == 200:
            split_information = str(html).split("\n")
            for i, line in enumerate(split_information):
                if searcher.search(line) is not None:
                    href = split_information[i]
        if href is not None:
            soup = BeautifulSoup(href, "html.parser")
            for item in soup.findAll("a"):
                link = item.get("href")
                return retval.format(link)
    return None


def hide_sensitive(args, command):
    """
    hide sensitive information out of the arguments

    :param args: sys.argv
    :param command: command option
    :return: 返回替换后的 完整的 sys.argv 的字符串
    """

    try:
        url_index = args.index(command) + 1
        # args[url_index + 1], 就是出问题的后面那个 option 的值, 比如 -u  "http://example.org" 这个args[url_index] 的值
        # 就是 'http://example.org', 这里是要用 * 全部替换掉这个值
        hidden_url = ''.join([x.replace(x, "*") for x in str(args[url_index])])
        args.pop(url_index)
        args.insert(url_index, hidden_url)
        return ' '.join(args)
    except:
        return ' '.join([item for item in sys.argv])


def request_issue_creation(exception_details):
    """
    create an issue instead of a firewall
    """
    import platform

    question = lib.print_format.prompt(
        "do you want to create an anonymized issue for the caught exception", "yN"
    )
    if question.lower().startswith("y"):
        # 检查最新版本, 暂时屏蔽
        # is_newest = lib.settings.check_version(speak=False)
        # if not is_newest:
        #     lib.formatter.error(
        #         "whatwaf is not the newest version, in order to create an issue, please update whatwaf"
        #     )
        #     exit(1)

        identifier = create_identifier(exception_details)

        for item in sys.argv:
            if item in lib.settings.SENSITIVE_ARGUMENTS:
                argv_data = hide_sensitive(sys.argv, item)
        title = "Whatwaf Unhandled Exception ({})".format(identifier)

        issue_creation_template = {
            "title": title,
            "body": "Whatwaf version: `{}`\n"
                    "Running context: `{}`\n"
                    "Traceback: \n```\n{}\n```\n"
                    "Running platform: `{}`".format(
                lib.settings.VERSION, argv_data, exception_details, platform.platform()
            )
        }

        issue_creation_json = json.dumps(issue_creation_template)
        if sys.version_info > (3,):  # python 3
            issue_creation_json = issue_creation_json.encode("utf-8")
        if not ensure_no_issue(identifier):
            req = Request(
                url="https://api.github.com/repos/ekultek/whatwaf/issues", data=issue_creation_json,
                headers={"Authorization": "token {}".format(get_token(lib.settings.TOKEN_PATH))}
            )
            try:
                urlopen(req, timeout=10).read()
                lib.print_format.info(
                    "this exception has been submitted successfully with the title '{}', URL: '{}'".format(
                        title, find_url(identifier)
                    )
                )
            except Exception as e:
                unprocessed_file_path = lib.settings.save_temp_issue(issue_creation_template)
                lib.print_format.fatal(
                    "caught an exception while trying to process request: {}, you can either create "
                    "this issue manually, or try again. if you have decided to create the issue "
                    "manually you can find the issue information in the following file: {}".format(
                        str(e), unprocessed_file_path
                    )
                )
        else:
            lib.print_format.error(
                "this exception has already been reported: '{}'".format(find_url(identifier))
            )


def request_firewall_issue_creation(path):
    """
    request the creation and create the issue

    :param path: example -> 完整的 fingerprint 文件保存路径, 例如 -> ~/.whatwaf/fingerprinters/FILENAME
    :return: no return
    """

    question = lib.print_format.prompt(
        "do you want to create an issue with the unknown firewall to possibly get it implemented", "yN"
    )
    if question.lower().startswith("y"):
        # 检查最新的版本, 暂时屏蔽
        # is_newest = lib.settings.check_version(speak=False)
        # if not is_newest:
        #     lib.formatter.error(
        #         "whatwaf is currently not the newest version, please update to request a firewall script creation"
        #     )
        #     exit(1)

        # gonna read a chunk of it instead of one line
        chunk = 4096
        with open(path) as data:
            # 产生一段 sha1 的hash, 不过只取 hash 的 1-9 位
            identifier = create_identifier(data.read(chunk))
            # gotta seek to the beginning of the file since it's already been read `4096` into it
            # seek() 方法用于移动文件读取指针到指定位置, 移到开头
            data.seek(0)
            full_fingerprint = data.read()

            # 这是要提交 issues 的
            issue_title = "Unknown Firewall ({})".format(identifier)

        for item in sys.argv:
            # SENSITIVE_ARGUMENTS = ("--proxy", "-u", "--url", "-D", "--data", "--pa", "-b", "--burp")
            if item in lib.settings.SENSITIVE_ARGUMENTS:
                # hide_sensitive(args, command)
                # 返回替换敏感 option 后的 完整的 sys.argv 的字符串
                # 不知道有什么用
                data = hide_sensitive(sys.argv, item)

        issue_data = {
            "title": issue_title,
            "body": "WhatWaf version: `{}`\n"
                    "Running context: `{}`\n"
                    "Fingerprint:\n```\n{}\n```".format(
                        # full_fingerprint 就是 fingerprint 文件的里的所有内容
                        lib.settings.VERSION, data, full_fingerprint
            )
        }

        # 变成 json 对象
        _json_data = json.dumps(issue_data)

        # python 3
        if sys.version_info > (3,):
            _json_data = _json_data.encode("utf-8")

        # 10 位的 sha1 hash
        # ensure_no_issue 如果返回 True, 就是在已知的问题中有, 如果为 False 就是没有在已知的问题中找到, 那就是新问题了
        if not ensure_no_issue(identifier):
            # 出现新问题的情况
            req = Request(
                url="https://api.github.com/repos/ekultek/whatwaf/issues", data=_json_data,
                # TOKEN_PATH="{}/content/data/auth.key".format(CUR_DIR)
                # 这个 get_token() 是返回一个 token 的
                headers={"Authorization": "token {}".format(get_token(lib.settings.TOKEN_PATH))}
            )
            try:
                urlopen(req, timeout=10).read()
                lib.print_format.info(
                    "this firewalls fingerprint has successfully been submitted with the title '{}', "
                    "URL '{}'".format(
                        issue_title, find_url(identifier)
                    )
                )
            except Exception as e:
                # 把 issus_data 写入文件, 位置在 -> ~/.whatwaf/unprocessed_issues, save_temp_issus() 会返回产生的文件的绝对路径
                unprocessed_file_path = lib.settings.save_temp_issue(issue_data)

                # 输出信息
                lib.print_format.fatal(
                    "caught an exception while trying to process request: {}, you can either create "
                    "this issue manually, or try again. if you have decided to create the issue "
                    "manually you can find the issue information in the following file: {}".format(
                        str(e), unprocessed_file_path
                    )
                )
        else:
            # 在原有的 issues 中有
            lib.print_format.error(
                "someone has already sent in this firewalls fingerprint here: {}".format(find_url(identifier))
            )
    lib.print_format.info("for further analysis the WAF fingerprint can be found in: '{}'".format(path))
