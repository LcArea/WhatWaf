# encoding: utf8
import os
import re
import json
import importlib
from termcolor import colored
try:
    import urlparse
except ImportError:
    # python 2.x doesn't have a ModuleNotFoundError so we'll just catch the exception I guess
    import urllib.parse as urlparse

from lib.settings import (
    TAMPERS_DIRECTORY,
    TAMPERS_IMPORT_TEMPLATE,
    URL_QUERY_REGEX,
    YAML_FILE_PATH,
    JSON_FILE_PATH,
    CSV_FILE_PATH,
    PLUGINS_IMPORT_TEMPLATE,
    PLUGINS_DIRECTORY,
    UNKNOWN_FIREWALL_NAME,
    WAF_REQUEST_DETECTION_PAYLOADS
)

from lib.database import insert_url
from lib.core.request import (
    get_random_agent,
    get_page,
    random_string,
    generate_random_post_string,
    validate_url,
    DetectionQueue,
    InvalidURLProvided,
    normalization_url
)
from lib.print_format import debug, warning, info, payload, success, prompt
from lib.core.savefile import write_to_file


class ScriptQueue(object):
    """
    This is where we will load all the scripts that we need to identify the firewall
    or to identify the possible bypass
    """

    def __init__(self, files_path, import_path, verbose=False):
        self.files = files_path
        self.path = import_path
        self.verbose = verbose
        self.skip_schema = ("detection.py", ".pyc", "__")
        self.script_type = ''.join(self.path.split(".")[1].split())[:-1]

    def load_scripts(self):
        """
        加载所有 plugins 目录下的 plugin, 并返回包含所有加载成功的 plugin 的 list
        包含所有已导入 plugin 的列表

        :return: retval 包含所有已导入 plugin 的列表
        """
        retval = []
        # file_list 是包含了所有的 plugins 目录下的 py 文件的列表
        file_list = [f for f in os.listdir(self.files) if not any(s in f for s in self.skip_schema)]

        for script in sorted(file_list):
            script = script[:-3]
            if self.verbose:
                debug("loading {} script '{}'".format(self.script_type, script))
            try:
                script = importlib.import_module(self.path.format(script))
                retval.append(script)
            except Exception:
                warning("failed to load tamper '{}', pretending it doesn't exist".format(script))

        # 包含所有已导入 plugin 的列表
        return retval


def encode(payload, script):
    """
    encode the payload with the provided tamper
    """
    script = importlib.import_module(script)
    return script.tamper(payload)


def find_failures(html, regs):
    """
    find failures in the response content
    """
    for reg in regs:
        if reg.search(html) is not None or html == "" or html is None:
            return True
    return False


def get_working_tampers(url, norm_response, payloads, **kwargs):
    """
    gather working tamper scripts

    working_tampers = set()
    working_tampers.add((tamper.__type__, tamper.tamper(tamper.__example_payload__), tamper)), 是个元组

    :param url: url
    :param norm_response: 正常不带 * 的 url
    :param payloads: payloads
    :param kwargs: 各种参数
    :return: working_tampers, 见简介
    """

    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    verbose = kwargs.get("verbose", False)
    # 最多搞定到 5 个有效 payload 就退出, 否则全部执行完
    tamper_int = kwargs.get("tamper_int", 5)
    provided_headers = kwargs.get("provided_headers", None)
    throttle = kwargs.get("throttle", 0)
    request_timeout = kwargs.get("timeout", 15)
    if request_timeout is None:
        warning("issue occured and the timeout resolved to None, defaulting to 15")
        request_timeout = 15

    failed_schema = (
        re.compile("404", re.I), re.compile("captcha", re.I),
        re.compile("illegal", re.I), re.compile("blocked", re.I),
        re.compile("ip.logged", re.I), re.compile("ip.address.logged", re.I),
        re.compile("not.acceptable", re.I), re.compile("access.denied", re.I),
        re.compile("forbidden", re.I), re.compile("400", re.I)
    )

    info("loading payload tampering scripts")
    # 返回包含所有 tampers 目录下的 py 文件 list
    tampers = ScriptQueue(
        TAMPERS_DIRECTORY, TAMPERS_IMPORT_TEMPLATE, verbose=verbose
    ).load_scripts()
    success("loading payload tampering scripts success")

    if tamper_int > len(tampers):
        warning(
            "the amount of tampers provided is higher than the amount of tampers available, "
            "ALL tampers will be tried (slow!)"
        )

        tamper_int = len(tampers)

    # working_tampers.add((tamper.__type__, tamper.tamper(tamper.__example_payload__), tamper)), 是个元组
    working_tampers = set()
    _, normal_status, _, _ = norm_response

    info("running tampering bypass checks")

    for tamper in tampers:
        if verbose:
            try:
                # 这里会出错 str(tamper).split(" ")[1] 会报 list index out of range 错误
                # debug("currently tampering with script '{}".format(str(tamper).split(" ")[1].split(".")[-1]))
                debug("currently tampering with script '{}".format(str(tamper)))
            except:
                pass

        for vector in payloads:
            vector = tamper.tamper(vector)

            if verbose:
                payload('using payload: {}'.format(vector.strip()))

            payloaded_url = "{}{}".format(url, vector)

            # 去请求 带有 payload 的 url
            # 需要加总请求次数
            _, status, html, _ = get_page(
                payloaded_url, user_agent=agent, proxy=proxy, provided_headers=provided_headers,
                throttle=throttle, timeout=request_timeout
            )

            if not find_failures(str(html), failed_schema):
                if verbose:
                    if status != 0:
                        debug("response code: {}".format(status))
                    else:
                        debug("unknown response detected")

                if status != 404:
                    if status == 200:
                        try:
                            working_tampers.add((tamper.__type__, tamper.tamper(tamper.__example_payload__), tamper))
                        except:
                            pass
            else:
                if verbose:
                    warning("failure found in response content")

            if len(working_tampers) == tamper_int:
                break

        if len(working_tampers) == tamper_int:
            break

    return working_tampers


def check_if_matched(normal_resp, payload_resp, step=1, verified=5):
    """
    verification that there is not protection on the target
    """
    # five seems like a good number for verification status, you can change it
    # by using the `--verify-num` flag
    matched = 0
    response = set()
    _, norm_status, norm_html, norm_headers = normal_resp
    _, payload_status, payload_html, payload_headers = payload_resp

    for header in norm_headers.keys():
        try:
            _ = payload_headers[header]
            matched += step
        except:
            response.add("header values differ when a payload is provided")

    if norm_status == payload_status:
        matched += step
    else:
        response.add("response status code differs when a payload is provided")

    if len(response) != 0:
        # 这个设置的 verifyed 感觉没什么用
        if matched <= verified:
            return response
        else:
            return None
    else:
        return None


def dictify_output(url, detect_firewalls, found_tampers):
    """
    send the output into a JSON format and return the JSON format

    :param url:
    :param detect_firewalls: 发现的 firewalls 指纹, 一般来说只会有一个指纹
    :param found_tampers:
    :return: json_retval 是由一个字典组成的
    """

    data_sep = colored("-" * 30, 'white')
    info("formatting output")
    retval = {"url": url}

    if isinstance(detect_firewalls, list):
        retval["identified firewall"] = [item for item in detect_firewalls]
        retval["is protected"] = True
    elif isinstance(detect_firewalls, str):
        retval["identified firewall"] = detect_firewalls
        retval["is protected"] = True
    else:
        retval["identified firewall"] = None
        retval["is protected"] = False

    if len(found_tampers) != 0:
        retval["apparent working tampers"] = []
        for item in found_tampers:
            # 自己的 payload
            _, _, load_tamper = item
            # 感觉这个没什么意义
            # to_append = str(load_tamper).split(" ")[1].replace("'", "")
            retval["apparent working tampers"].append(load_tamper)
    else:
        retval["apparent working tampers"] = None

    retval_json = json.dumps(retval, indent=4, sort_keys=True)
    print("{}\n{}\n{}".format(data_sep, retval_json, data_sep))
    return retval_json


def display_found_tampers(found_tampers):
    """
    produce the results of the tamper scripts, if any this
    这个函数是用来美化输出的, 加入 found_tampers 里面有东西, 就美化输出出来

    :param found_tampers: 是个集合, 形如 ->
                           working_tampers.add((
                               tamper.__type__,
                               tamper.tamper(tamper.__example_payload__),
                               tamper
                           ))
    :return: None
    """

    spacer = colored("-" * 30, 'white')

    if len(found_tampers) > 0:
        success("apparent working tampers for target:")

        print(spacer)
        for i, tamper in enumerate(found_tampers, start=1):
            description, example, load_tamper = tamper
            # # 会有极大的概率出错
            # try:
            #     load_tamper = str(load_tamper).split(" ")[1].split("'")[1]
            # except IndexError:
            #     pass

            print("(#{}) description: tamper payload by {}\nexample: '{}'\nload tamper: {}".format(
                i, description, example, load_tamper
            ))

            if i != len(found_tampers):
                print("\n")
        print(spacer)
    else:
        warning("no valid bypasses discovered with provided payloads")


def produce_results(found_tampers):
    """
    produce the results of the tamper scripts, if any this
    输出更好看的格式

    :param found_tampers: 发现的所有 tampers
    :return: None
    """

    spacer = "-" * 30
    if len(found_tampers) > 0:
        success("apparent working tampers for target:")

        print(spacer)
        for i, tamper in enumerate(found_tampers, start=1):
            description, example, load = tamper
            try:
                load = str(load).split(" ")[1].split("'")[1]
            except IndexError:
                pass
            print("(#{}) description: tamper payload by {}\nexample: '{}'\nload path: {}".format(
                i, description, example, load
            ))
            if i != len(found_tampers):
                print("\n")
        print(spacer)
    else:
        warning("no valid bypasses discovered with provided payloads")


def detection_main(
        url,
        payloads,
        cursor,
        request_type="GET",
        post_data=None,
        user_agent=get_random_agent(),
        provided_headers=None,
        proxy=None,
        verbose=False,
        skip_bypass_check=False,
        verification_number=None,
        # 暂时屏蔽, 没什么卵用
        # fingerprint_waf=False,
        formatted=False,
        tamper_int=5,
        use_yaml=False,
        use_json=False,
        use_csv=False,
        traffic_file=None,
        throttle=0,
        request_timeout=15,
        # 这个 determine_server 应该要默认开启
        # determine_server=False,
        threaded=None,
        force_file_creation=False,
        save_file_copy_path=None):
    """
    main detection function

    :param url: url
    :param payloads: payloads
    :param cursor: databse cursor
    :param request_type: get or post
    :param post_data: post data you given to
    :param user_agent: User Agent
    :param provided_headers: custom headers Dic type
    :param proxy: proxy
    :param verbose: verbose mode default False
    :param skip_bypass_check: skip payload bypass check
    :param verification_number:
    :param formatted:
    :param tamper_int:
    :param use_yaml:
    :param use_json:
    :param use_csv:
    :param traffic_file:
    :param throttle:
    :param request_timeout:
    :param threaded:
    :param force_file_creation:
    :param save_file_copy_path:
    :return: response count 发送的总请求的数量
    """

    # 保险, 还是初始化一下
    url = normalization_url(url)
    if url[-1] != "/":
        url += "/"

    current_url_netloc = urlparse.urlparse(url).netloc

    # 如果没有检测出 url 中的参数, 可能会干扰检测结果, 如果是 POST 请求呢?
    if URL_QUERY_REGEX.search(str(url)) is None and request_type.lower() == "get":
        warning(
            "URL does not appear to have a query (parameter), this may interfere with the detection results"
        )

    # 是否在 url 中有 * 的地方放置 attack payload?
    if '*' in url:
        choice = prompt(
            "custom placement marker found in URL `*` would you like to use it to place the attacks", "yN"
        )
        if choice.lower().startswith("y"):
            use_placement = True
        else:
            use_placement = False
    else:
        use_placement = False

    if use_yaml:
        file_path = YAML_FILE_PATH
    elif use_json:
        file_path = JSON_FILE_PATH
    elif use_csv:
        file_path = CSV_FILE_PATH
    else:
        file_path = None

    try:
        file_start = url.split("/")[2].split(".")[1]

        if use_json:
            ext = ".json"
        elif use_yaml:
            ext = ".yaml"
        elif use_csv:
            ext = ".csv"
        else:
            ext = '.txt'

        filename = "{}{}".format(file_start, ext)
    except:
        if use_json:
            file_type = "json"
        elif use_csv:
            file_type = 'csv'
        elif use_yaml:
            file_type = 'yaml'
        else:
            file_type = 'txt'

        filename = random_string(length=10, file_type=file_type)

    info("request type: {}".format(request_type))

    # 检查是否为无效 POST data
    if request_type.lower() == 'post':
        if len(post_data) == 0:
            warning("no POST string supplied generating random")
            post_data = generate_random_post_string()
            info("random POST string to be sent: '{}'".format(post_data))
        elif post_data is not None and post_data != "":
            info("POST string to be sent: '{}'".format(post_data))

    # 如果不是有效 url, 就抛出异常
    if validate_url(url) is None:
        raise InvalidURLProvided

    info("gathering HTTP responses")

    if threaded:
        # 如果指定了 thread
        responses_list = DetectionQueue(
            url, payloads, proxy=proxy, agent=user_agent, verbose=verbose,
            provided_headers=provided_headers, traffic_file=traffic_file, throttle=throttle,
            timeout=request_timeout, request_type=request_type, post_data=post_data, threaded=threaded,
            placement=use_placement
        ).threaded_get_response()
    else:
        # 这个 response 是形如多个 -> ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
        # 这样的集合
        responses_list = DetectionQueue(
            url, payloads,
            request_type=request_type,
            post_data=post_data,
            provided_headers=provided_headers,
            agent=user_agent,
            proxy=proxy,
            verbose=verbose,
            # save_fingerprint=fingerprint_waf,
            # --traffic FILENAME
            # traffic_file=traffic_file,
            throttle=throttle,
            timeout=request_timeout,
            placement=use_placement
        ).get_response()

    # 指定了 --traffic, 保存进文件
    if traffic_file is not None:
        with open(traffic_file, "a+") as traffic:
            for i, item in enumerate(responses_list, start=1):
                param, status_code, content, headers = item
                traffic.write(
                    "HTTP Request #{}\n{}\nRequest Status Code: {}\n<!--\n{} HTTP/1.1\n{}\n-->{}\n\n\n".format(
                        i,
                        "-" * 30,
                        status_code,
                        param,
                        "\n".join(["{}: {}".format(h, v) for h, v in headers.items()]),
                        content
                    )
                )

    info("gathering normal response to compare against")

    # 上面是请求的带有 payload 的路径和 爆破 admin 路径的 url, 这里是请求原有的 url, 但是那url中的 * 怎么办?
    normal_response = get_page(
        url, proxy=proxy, user_agent=user_agent, provided_headers=provided_headers, throttle=throttle,
        timeout=request_timeout, request_method=request_type, post_data=post_data
    )

    # --determine-webserver
    # 就是检查 response headers 中的 server, 例如 Apache2 什么的
    # 默认带上
    # if determine_server:
    found_webserver = None
    # 这个 response_list 是形如多个 -> ('GET https://example.org', '200 OK', 'soup对象', "{'User_Agent': 'fuck'}")
    # 这样的集合
    headers = {}
    for resp in responses_list:
        headers = resp[-1]

    for k in headers.keys():
        if k.lower() == "server":
            found_webserver = headers[k]
            break
    if found_webserver is None:
        warning("unable to determine web server")
    else:
        success("web server determined as: {}".format(found_webserver))

    # 加载 所有的 plugins, 然后返回所有的已导入的 plugin 的列表
    info("loading firewall detection scripts")
    loaded_plugins = ScriptQueue(
        PLUGINS_DIRECTORY, PLUGINS_IMPORT_TEMPLATE, verbose=verbose
    ).load_scripts()
    success("loading firewall detection scripts success")

    info("running firewall detection checks")

    # plus one for get_page() call
    request_count = len(responses_list) + 1
    amount_of_products = 0
    detected_protections = set()
    # temp = []
    for item in responses_list:
        item = item if item is not None else normal_response
        _, status, html, headers = item

        for plugin in loaded_plugins:
            try:
                if plugin.detect(str(html), status=status, headers=headers) is True:
                    # 先丢着
                    # temp.append(plugin.__product__)
                    # plugin 的介绍不可能是 Unknown Firewall
                    # if plugin.__product__ == UNKNOWN_FIREWALL_NAME and len(temp) == 1 and status != 0:
                    #     warning("unknown firewall detected saving fingerprint to log file")
                    #     path = create_fingerprint(url, html, status, headers)
                    #     return request_firewall_issue_creation(path)
                    # else:
                    #     detected_protections.add(plugin.__product__)
                    detected_protections.add(plugin.__product__)
            except Exception:
                pass

    if len(detected_protections) > 0:
        if UNKNOWN_FIREWALL_NAME not in detected_protections:
            amount_of_products += 1

        if len(detected_protections) > 1:
            for i, _ in enumerate(list(detected_protections)):
                amount_of_products += 1

    if amount_of_products == 1:
        # 获取检测到的产品的 __product__ 一般只有一个
        detected_protections = list(detected_protections)[0]

        success(
            "detected website protection identified as '{}', searching for bypasses".format(detected_protections)
        )

        # 如果没有指定 --skip
        if not skip_bypass_check:
            # get_working_tampers() 返回一个 working_tampers 集合
            # working_tampers = set()
            # working_tampers.add((tamper.__type__, tamper.tamper(tamper.__example_payload__), tamper)), 是个元组
            found_working_tampers = get_working_tampers(
                url, normal_response, payloads, proxy=proxy, agent=user_agent, verbose=verbose,
                tamper_int=tamper_int, provided_headers=provided_headers, throttle=throttle,
                timeout=request_timeout
            )

            # 没加 --format 就只是美化输出
            if not formatted:
                # display_found_tampers 是美化输出的, 输出 found_working_tampers
                display_found_tampers(found_working_tampers)
            else:
                # dictify_output return json_retval 是由一个字典组成的
                # 这个字典包含 {
                #     "url": url,
                #     "identified firewall": detect_firewalls,
                #     "is protected": True,
                #     "apparent working tampers": "自己输入的 payload"
                # }
                dict_data_output = dictify_output(url, detected_protections, found_working_tampers)

                # 写入文件
                # 注意, 这个 filename 可能是 None, 不一定会指定 CSV、JSON 或者 YAML
                if file_path:
                    written_file_path = write_to_file(
                        filename, file_path, dict_data_output,
                        write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                        save_copy_to=save_file_copy_path
                    )
                    if written_file_path is not None:
                        info("data has been written to file: '{}'".format(written_file_path))

            """
            cached_urls table field ->
            id
            uri
            working_tampers DEFAULT 'N/A', "
            identified_protections DEFAULT 'N/A',"
            identified_webserver DEFAULT 'N/A'"
            """
            inserted_into_database_results = insert_url(
                # found_webserver 是检查是否 response 的 header 中有 server 字段
                # found_working_tampers 和 detected_protections 如果不止一个, 就用 , 拼接
                cursor, current_url_netloc, found_working_tampers, detected_protections, webserver=found_webserver
            )
        else:
            # 指定了 --skip, 就会跳过 tamper 这个字段的写入
            warning("skipping bypass checks")

            # --format
            if formatted:
                # 格式化输出的
                dict_data_output = dictify_output(url, detected_protections, [])

                # 写入文件
                # 注意, 这个 filename 可能是 None, 不一定会指定 CSV、JSON 或者 YAML
                written_file_path = write_to_file(
                    filename, file_path, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                    save_copy_to=save_file_copy_path
                )

                # 也就是 如果指定了 json csv yaml 中的任何一个
                if written_file_path is not None:
                    info("data has been written to file: '{}'".format(written_file_path))

            if isinstance(detected_protections, str):
                # 在 list 的基础上再加个 []
                detected_protections = [detected_protections]

            # 因为选择了 --skip 所以跳过 tamper 阶段
            inserted_into_database_results = insert_url(
                 cursor, current_url_netloc, [], detected_protections, webserver=found_webserver
            )

    elif amount_of_products == 0:
        # 没找到
        warning("no protection identified on target, verifying")

        if verification_number is None:
            verification_number = 5

        verification_normal_response = get_page(
            url, proxy=proxy, user_agent=user_agent, provided_headers=provided_headers, throttle=throttle,
            timeout=request_timeout, request_method=request_type, post_data=post_data
        )

        # 随便从默认的 payload 文件中拿第四个
        payloaded_url = "{}{}".format(url, WAF_REQUEST_DETECTION_PAYLOADS[3])

        verification_payloaded_response = get_page(
            payloaded_url, proxy=proxy, user_agent=user_agent, provided_headers=provided_headers, throttle=throttle,
            timeout=request_timeout, request_method=request_type, post_data=post_data
        )

        # check_if_matched 返回 response 集合 或者返回 None, 当 normal url 和 加了 payload 的 url 的返回头一样时候, 肯定就
        # 是返回的 None
        results = check_if_matched(
            verification_normal_response, verification_payloaded_response,
            verified=verification_number
        )

        if results is not None:
            data_sep = colored("-" * 30, 'white')
            info("target seems to be behind some kind of protection for the following reasons:")

            print(data_sep)
            for i, content in enumerate(results, start=1):
                print("[{}] {}".format(i, content))
            print(data_sep)

            # 暂时屏蔽
            # 这一段是说明, 如果 waf 的指纹没检测出来, 但是进行比较之后 又发现了不同, 说明指纹库不够强大, 这时候会发送 issues 到
            # 作者的 github 上
            # _, status, html, headers = verification_payloaded_response
            # if status != 0:
            #     path = create_fingerprint(url, html, status, headers)
            #     request_firewall_issue_creation(path)
            # else:
            #     warning(
            #         "status code returned as `0` meaning that there is no content in the webpage, "
            #         "issue will not be created"
            #     )

            inserted_into_database_results = insert_url(
                current_url_netloc, [], [], cursor, webserver=found_webserver
            )
        else:
            # 说明没有发现不同
            success("no protection identified on target")

            if formatted:
                if not force_file_creation:
                    warning(
                        "no data will be written to files since no protection could be identified, "
                        "to force file creation pass the `--force-file` argument"
                    )
                else:
                    # if the argument `--force-file` is passed we will create the file
                    # anyways, this should give users who are relying on the JSON files
                    # for thirdparty information a chance to get the data out of the directory
                    # then they can easily parse it without problems.
                    warning("forcing file creation without successful identification")
                    dict_data_output = dictify_output(url, None, [])
                    written_file_path = write_to_file(
                        filename, file_path, dict_data_output,
                        write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                        save_copy_to=save_file_copy_path
                    )

                    if written_file_path is not None:
                        info("data has been written to file: '{}'".format(written_file_path))

            inserted_into_database_results = insert_url(
                current_url_netloc, [], [], cursor, webserver=found_webserver
            )

    else:
        # 不止一个 waf protections
        success("multiple protections identified on target{}:".format(
            " (unknown firewall will not be displayed)" if UNKNOWN_FIREWALL_NAME in detected_protections else ""
        ))

        detected_protections = [item for item in list(detected_protections)]

        for i, protection in enumerate(detected_protections, start=1):
            if not protection == UNKNOWN_FIREWALL_NAME:
                success("#{} '{}'".format(i, protection))

        if not skip_bypass_check:
            info("searching for bypasses")

            found_working_tampers = get_working_tampers(
                url, normal_response, payloads, proxy=proxy, agent=user_agent, verbose=verbose,
                tamper_int=tamper_int, throttle=throttle, timeout=request_timeout, provided_headers=provided_headers
            )

            if not formatted:
                # 将 tampers 输出的更加好看
                produce_results(found_working_tampers)
            else:
                # dictify_ouput 的返回 -> json_retval 是由一个字典组成的
                dict_data_output = dictify_output(url, detected_protections, found_working_tampers)

                written_file_path = write_to_file(
                    filename, file_path, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                    save_copy_to=save_file_copy_path
                )
                if written_file_path is not None:
                    info("data has been written to file: '{}'".format(written_file_path))
            # 写入数据库
            inserted_into_database_results = insert_url(
                current_url_netloc, found_working_tampers, detected_protections, cursor, webserver=found_webserver
            )
        else:
            # 跳过 tampers 的检查
            warning("skipping bypass tests")
            if formatted:
                dict_data_output = dictify_output(url, detected_protections, [])
                written_file_path = write_to_file(
                    filename, file_path, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                    save_copy_to=save_file_copy_path
                )
                if written_file_path is not None:
                    info("data has been written to file: '{}'".format(written_file_path))
            inserted_into_database_results = insert_url(
                current_url_netloc, [], detected_protections, cursor, webserver=found_webserver
            )

    if inserted_into_database_results:
        info("URL has been cached for future use")

    # 返回请求的总数量
    return request_count
