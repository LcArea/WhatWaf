# encoding: utf8
from lib.print_format import warning, info, error, debug, payload
from lib.settings import ROOT_DIR, PROTOCOL_DETECTION, POST_STRING_NAMES_PATH, URL_VALIDATION, RAND_HOMEPAGES
from lib.core.savefile import create_fingerprint
import random
import requests
from bs4 import BeautifulSoup
import time
import string
import urlparse
import threading
import re
import json
try:
    import queue
except ImportError:
    import Queue as queue


# 自定义处理异常的类, 继承了 Exception
class InvalidURLProvided(Exception):
    pass


def configure_request_headers(user_agent=None, proxy=None, random_agent=False, tor=None, tor_port=9050):
    """
    configure the HTTP request headers with a user defined
    proxy, Tor, or a random User-Agent from the user-agent
    file

    :param user_agent: User Agent from custom request
    :param proxy: Whether use proxy, default None
    :param random_agent: Whether use random User Agent, strong recommend
    :param tor: Whether use tor proxy, default None
    :param tor_port: setting custom tor port
    :return: proxy, user_agent
    """

    supported_proxies = ("socks5", "socks4", "http", "https")

    invalid_msg = "invalid switches detected, switch {} cannot be used in conjunction with switch {}"
    proxy_msg = "running behind proxy '{}'"

    # --proxy 和 --tor 不能同时被设置
    if proxy is not None and tor:
        error(invalid_msg.format("--tor", "--proxy"))
        exit(1)

    # --ra 和 --pa 不能在一起
    if user_agent is not None and random_agent:
        error(invalid_msg.format("--ra", "--pa"))
        exit(1)

    # tor 默认是 socket5://127.0.0.1:9050 端口
    if tor:
        proxy = "socks5://127.0.0.1:{}".format(tor_port)

    if user_agent is None:
        user_agent = get_random_agent()

    if random_agent:
        # 从 whatwaf/content/data/user_agent.txt 中随便挑一个 user_agent 请求头
        user_agent = get_random_agent()

    # proxy 不为空
    if proxy is not None:
        if any(item in proxy for item in supported_proxies):
            info(proxy_msg.format(proxy))
        else:
            error(
                "you did not provide a supported proxy protocol, "
                "supported protocols are '{}'. check your proxy and try again".format(
                    ", ".join([p for p in supported_proxies])
                )
            )
            exit(1)
    else:
        # proxy 为 Null
        warning(
            "it is highly advised to use a proxy when using WhatWaf. do so by passing the proxy flag "
            "(eg `--proxy http://127.0.0.1:9050`) or by passing the Tor flag (eg `--tor`)"
        )

    #  如果 user_agent 请求头不为空
    if user_agent is not None:
        info("using User-Agent '{}'".format(user_agent))

    return proxy, user_agent


def get_random_agent(path="{}/data/txt/user_agents.txt"):
    """
    grab a random user-agent from the file to pass as
    the HTTP User-Agent header
    """
    with open(path.format(ROOT_DIR)) as agents:
        items = [agent.strip() for agent in agents.readlines()]
        return random.choice(items)


def random_string(acceptable=string.ascii_letters, file_type='txt', length=5):
    """
    create a random string for some of the tamper scripts that need a random string in order to work properly

    :param acceptable: 生成随机数的规则
    :param length: random string length
    :param file_type: 做文件后缀, 例如 txt
    :return: filename 返回随机产生的字符
    """

    # random_chars 是一个 随机字符 列表
    random_chars = [random.choice(acceptable) for _ in range(length)]

    if file_type:
        return "{}.{}".format(''.join(random_chars), file_type)
    else:
        # 防止 file_type 为 None, 增加容错性
        return "{}.{}".format(''.join(random_chars), 'txt')


def generate_random_post_string(amount=2):
    """
    generate a random POST string from a list of provided keywords
    """
    send_string_retval = []
    post_name_retval = set()
    for _ in range(amount):
        send_string_retval.append(
            random_string(
                acceptable=string.ascii_letters + string.digits,
                length=random.choice(range(4, 18))
            )
        )
    # POST_STRING_NAMES_PATH = "{}/data/post_strings.lst".format(CUR_DIR)
    # 从 whatwaf/content/data/post_strings.lst 文件中随机挑选两个作为 post data
    with open(POST_STRING_NAMES_PATH, "r") as data:
        line_data = [c.strip() for c in data.readlines()]
        while len(post_name_retval) != 2:
            post_name_retval.add(random.choice(line_data))

    # 变成列表
    post_name_retval = list(post_name_retval)
    post_string_retval_data = (post_name_retval[0], send_string_retval[0], post_name_retval[1], send_string_retval[1])
    return "{}={}&{}={}".format(*post_string_retval_data)


def get_query(url):
    """
    get the query parameter out of a URL
    """
    data = urlparse.urlparse(url)
    query = "{}?{}".format(data.path, data.query)
    return query


def get_page(url, proxy=None, user_agent=get_random_agent(), provided_headers=None, throttle=0, timeout=15,
             request_method='GET', post_data=None):
    """
     get the website page, this will return a `tuple`
    containing the status code, HTML and headers of the
    requests page

    :param url: url
    :param proxy: proxy
    :param user_agent: User Agent
    :param provided_headers: headers
    :param throttle: throttle per request
    :param timeout: timeout per request for whiting response
    :param request_method: get or post?
    :param post_data: post data
    :return: 形如 -> ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
    """

    # 为什么要加入随机字符串?, 这里将随机字符串填入 关键 parameter 中
    if post_data:
        # 如果 post_data 不为空
        post_data_list = list(post_data)
        for i, item in enumerate(post_data_list):
            if item == "=":
                post_data_list[i] = "{}{}{}".format(post_data_list[i - 1], post_data_list[i], random_string(length=7))

        post_data = ''.join(post_data_list)

    if request_method == "POST":
        req = requests.post
    else:
        req = requests.get

    if provided_headers is None:
        headers = {"Connection": "close", "User-Agent": user_agent}
    else:
        headers = {}
        if type(provided_headers) == dict:
            for key, value in provided_headers.items():
                headers[key] = value
            headers["User-Agent"] = user_agent
        else:
            headers = provided_headers
            headers["User-Agent"] = user_agent
    proxies = {} if proxy is None else {"http": proxy, "https": proxy}
    error_retval = ("", 0, "", {})

    # throttle the requests from here
    time.sleep(throttle)

    try:
        req = req(url, headers=headers, proxies=proxies, timeout=timeout, data=post_data, verify=False)
        soup = BeautifulSoup(req.content, "html.parser")

        # return 形如 -> ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
        return "{} {}".format(request_method, get_query(url)), req.status_code, soup, req.headers
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.TooManyRedirects):
        return error_retval
    except Exception as e:
        if "timed out" in str(e):
            return error_retval


def normalization_url(url, ssl=False):
    """
    check if a protocol is given in the URL if it isn't we'll auto assign it
    """

    # PROTOCOL_DETECTION.search(url) 是检测 url 有没有加上 http 或者 https
    if PROTOCOL_DETECTION.search(url) is None:
        if ssl:
            warning("no protocol discovered, assigning HTTPS (SSL)")
            return "https://{}".format(url.strip())
        else:
            warning("no protocol discovered assigning HTTP")
            return "http://{}".format(url.strip())
    else:
        if ssl:
            info("forcing HTTPS (SSL) connection")
            items = PROTOCOL_DETECTION.split(url)
            item = items[-1].split("://")
            item[0] = "https://"
            return ''.join(item)
        else:
            return url.strip()


def test_target_connection(url, post_data, proxy, user_agent, headers):
    """
    test connection to the target URL before doing anything else

    :param url: url
    :param post_data: post data
    :param proxy: proxy
    :param user_agent: User Agent
    :param headers: headers
    :return: status
    """

    test_times = 2
    failed = 0

    for _ in range(test_times):
        results = get_page(url, proxy=proxy, post_data=post_data, user_agent=user_agent, provided_headers=headers)
        _, status, _, _ = results
        # 怎么会有 status == 0 的?
        if status == 0:
            failed += 1

    if failed == 1:
        return "acceptable"
    elif failed == 2:
        return "nogo"
    else:
        return "ok"


def validate_url(url):
    """
    validate a provided URL
    """
    return URL_VALIDATION.match(url)


def strip_url(url):
    """
    strip url, 形如 -> ('http:', 'www.baidu.com')

    :param url:
    :return:
    """
    return url.split("/")[0], url.split("/")[2]


class DetectionQueue(object):
    """
    Queue to add the HTML requests into, it will return a `tuple` containing status, html, and headers along with
    the amount of requests that have been made
    """

    def __init__(self, url, payloads, **kwargs):
        self.url = url
        self.payloads = payloads
        self.request_type = kwargs.get("request_type", "GET")
        self.post_data = kwargs.get("post_data", None)
        self.provided_headers = kwargs.get("provided_headers", None)
        self.agent = kwargs.get("agent", get_random_agent())
        self.proxy = kwargs.get("proxy", None)
        self.verbose = kwargs.get("verbose", False)
        # 不要这个
        # self.save_fingerprint = kwargs.get("save_fingerprint", False)
        # 这个 traffic file 暂时还没有实现
        self.traffic_file = kwargs.get("traffic_file", None)
        self.throttle = kwargs.get("throttle", 0)
        self.timeout = kwargs.get("timeout", 15)
        self.threads = kwargs.get("threaded", None)
        self.placement = kwargs.get("placement", False)
        self.threading_queue = queue.Queue()
        self.response_retval_list = []

    def get_response(self):
        for i, waf_vector in enumerate(self.payloads):
            # 如果给出的 url 没有 * 可 payload 点, 就直接追加到 url 的后面
            if not self.placement:
                primary_url = self.url + "{}".format(waf_vector)
            else:
                # 那就是在一个 url 中只会有一个 *, 只有一个可 payload 的点, 会把 * 替换成 payload
                # 这里需要加强一下, 如果有 多个 *
                url = self.url.split("*")
                primary_url = "{}{}{}".format(url[0], waf_vector, url[len(url) - 1])
            # secondary_url 是爆破 admin 路径的 但是只选择了一个, 就没什么卵用
            secondary_url = strip_url(self.url)
            secondary_url = "{}//{}".format(secondary_url[0], secondary_url[1])
            secondary_url = "{}/{}".format(secondary_url, random.choice(RAND_HOMEPAGES))

            # 如果指定了 --verbose, 就打印出传入的 payload 参数
            if self.verbose:
                payload("using payload: {}".format(waf_vector.strip()))

            try:
                if self.verbose:
                    debug("trying: '{}'".format(primary_url))
                response_retval = get_page(
                    # get_page return 形如 ->
                    # ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
                    primary_url, user_agent=self.agent, proxy=self.proxy, provided_headers=self.provided_headers,
                    throttle=self.throttle, timeout=self.timeout, request_method=self.request_type,
                    post_data=self.post_data
                )
                self.response_retval_list.append(response_retval)

                _, response_status_code, _, _ = response_retval
                if self.verbose:
                    info("response status code: {}".format(response_status_code))

                if self.verbose:
                    debug("trying: {}".format(secondary_url))

                # 请求给出 url 的主目录, 用了admin爆破字典, 因为是从 RAND_HOMEPAGES 中随机抽取了一个, 所以不一定会成功返回 200
                # response_retval 是一个列表, 列表的元素是元组
                response_retval = get_page(
                    # return -> ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
                    secondary_url, user_agent=self.agent, proxy=self.proxy, provided_headers=self.provided_headers,
                    # throttle -> Provide a sleep time per request (*default=0), 发送各种请求的时间间隔
                    throttle=self.throttle, timeout=self.timeout, request_method=self.request_type,
                    post_data=self.post_data
                )
                self.response_retval_list.append(response_retval)

                _, response_status_code, _, _ = response_retval
                if self.verbose:
                    info('response status code: {}'.format(response_status_code))

            except Exception as e:
                # 事实上应该返回各种请求码, 例如拒绝, 找不到页面, 而不应该出错
                if "ECONNRESET" in str(e):
                    warning(
                        "possible network level firewall detected (hardware), received an aborted connection"
                    )
                    self.response_retval_list.append(None)
                else:
                    error(
                        "failed to obtain target meta-data with payload {}, error: '{}'".format(
                            waf_vector.strip(), str(e)
                        )
                    )
                    self.response_retval_list.append(None)

            # 暂时关闭
            # 如果指定了 --fingerprint, 为什么只保存一个?
            # 这里只会保存第一个 payload 请求和爆破 index 页面请求
            # if self.save_fingerprint:
            #     create_fingerprint(
            #         self.url,
            #         # get_page return 形如 ->
            #         # ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
            #         # Soup object
            #         response_retval[0][2],
            #         # response code
            #         response_retval[0][1],
            #         # User Agent
            #         response_retval[0][3],
            #         # 形如 -> GET https://www.example.com
            #         req_data=response_retval[0][0],
            #         speak=True
            #     )

        # get_page return 形如多个 -> ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
        # 这样的集合
        # 有几个 payload 就请求了几次
        return self.response_retval_list

    def threader(self):
        # not sure why this is wrapped in parentheses
        while True:
            url_thread, waf_vector = self.threading_queue.get()
            try:
                if self.verbose:
                    debug("trying: '{}'".format(url_thread))

                response_retval = get_page(
                    url_thread, user_agent=self.agent, proxy=self.proxy, provided_headers=self.provided_headers,
                    throttle=self.throttle, timeout=self.timeout, request_method=self.request_type,
                    post_data=self.post_data
                )
                self.response_retval_list.append(response_retval)

                _, response_status_code, _, _ = response_retval
                if self.verbose:
                    info('response status code: {}'.format(response_status_code))

            except Exception as e:
                if "ECONNRESET" in str(e):
                    warning(
                        "possible network level firewall detected (hardware), received an aborted connection"
                    )
                    self.response_retval_list.append(None)
                else:
                    error(
                        "failed to obtain target meta-data with payload {}, error: '{}'".format(
                            waf_vector.strip(), str(e)
                        )
                    )
                    self.response_retval_list.append(None)

                    # 暂时关闭
                    # if self.save_fingerprint:
                    #     create_fingerprint(
                    #         self.url,
                    #         self.response_retval_list[0][2],
                    #         self.response_retval_list[0][1],
                    #         self.response_retval_list[0][3],
                    #         req_data=self.response_retval_list[0][0],
                    #         speak=True
                    #     )

            self.threading_queue.task_done()

    # def threaded_get_response_helper(self, url_thread, waf_vector):
    def threaded_get_response(self):
        """
        将所有需要请求的 payload 加入队列中去, 然后用多线程去取任务, 这样速度会快很多
        :return:
        """

        for i, waf_vector in enumerate(self.payloads):
            if not self.placement:
                # 如果没有 * 在 url 中, 就在 url 后面追加
                primary_url = self.url + "{}".format(waf_vector)
            else:
                # 否则用 payload 代替 *
                url = self.url.split("*")
                primary_url = "{}{}{}".format(url[0], waf_vector, url[len(url) - 1])

            # secondary_url 是爆破 admin 路径的, 但是肯定没有什么卵用
            secondary_url = strip_url(self.url)
            secondary_url = "{}//{}".format(secondary_url[0], secondary_url[1])
            secondary_url = "{}/{}".format(secondary_url, random.choice(RAND_HOMEPAGES))

            if self.verbose:
                payload("using payload: {}".format(waf_vector.strip()))

            self.threading_queue.put((primary_url, waf_vector))
            self.threading_queue.put((secondary_url, waf_vector))

        for i in range(self.threads):
            t = threading.Thread(target=self.threader)
            t.daemon = True
            t.start()

        self.threading_queue.join()

        # threaded_get_response_helper 中有个 self.response_retval_list.append(),
        # 但是加入 response_retval 列表中的顺序可能会被打乱
        return self.response_retval_list


def parse_burp_request(filename):
    """
    parse an XML file from Burp Suite and make a request based on what is parsed

    :param filename: file
    :return: retval -> 包含 url 的列表
    """

    burp_request_regex = re.compile("<url><\S.cdata.", re.I)
    tmp = set()
    retval = []

    with open(filename) as xml:
        for line in xml.readlines():
            line = line.strip()
            if burp_request_regex.search(line) is not None:
                tmp.add(line)
    tmp = list(tmp)
    for url in tmp:
        url = re.split("<(.)?url>", url)[2].split("CDATA")[-1].replace("[", "").replace("]]", "").replace(">", "")
        retval.append(url)
    return retval


def parse_googler_file(filepath):
    """
    parse a JSON file provided from a Googler search
    """
    retval = set()
    try:
        with open(filepath) as f:
            data = json.load(f)
            for item in data:
                retval.add(item["url"])
    except IOError:
        retval = None
    return retval


class HTTP_HEADER:
    """
    HTTP request headers list, putting it in a class because
    it's just easier to grab them then to retype them over
    and over again
    """
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_CACHE = "X-Cache"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"
    X_FRAME_OPT = "X-Frame-Options"
    X_FORWARDED_FOR = "X-Forwarded-For"
    X_SERVER = "X-Server"
    X_BACKSIDE_TRANS = "X-Backside-Transport"

