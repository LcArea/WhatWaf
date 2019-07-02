#!/usr/bin/env python
# encoding: utf8
import sys
import time
import subprocess
from lib.cmdline import CmdLineParser
from lib.firewall_found import request_issue_creation
from lib.core.detection import detection_main
from lib.core.encoding import get_encoding_list, encode
from lib.print_format import error, info, fatal, warning, success
from termcolor import colored

from lib.database import (
    initialize,
    fetch_data,
    display_cached,
    check_url_cached,
    insert_payload,
    export_payloads
)
from lib.core.request import (
    configure_request_headers,
    normalization_url,
    test_target_connection,
    parse_burp_request,
    InvalidURLProvided
)
from lib.settings import (
    WAF_REQUEST_DETECTION_PAYLOADS,
    BANNER,
    HOME,
    PLUGINS_DIRECTORY,
    TAMPERS_DIRECTORY,
    RESULTS_TEMPLATE
)


def main():
    spacer = colored("-" * 30, 'white')

    print BANNER
    opts = CmdLineParser().cmd_parser()

    if not len(sys.argv[1:]):
        error("You failed to provide an option, redirecting to help menu")
        # 停顿2秒之后再显示 help banner
        time.sleep(2)
        print
        CmdLineParser().cmd_parser(get_help=True)
    else:
        # if you feel that you have to many folders or data in the whatwaf home folder
        # we'll give you an option to clean it free of charge
        if opts.cleanHomeFolder:
            # 对文件的权限或者 移动 拷贝什么的
            import shutil
            try:
                warning(
                    "cleaning the home folder: {home}, if you have installed with setup.sh, "
                    "this will erase the executable script along with everything inside "
                    "of the {home} directory (fingerprints, scripts, copies of whatwaf, etc) "
                    "if you are sure you want to do this press ENTER now. If you changed "
                    "your mind press CNTRL-C now".format(home=HOME)
                )
                # you have three seconds to change your mind
                raw_input("")
                info("attempting to clean up home folder")
                # 这个 HOME 是程序根目录下的 .whatwaf 文件夹, 例如 /root/.whatwaf
                # 删了这个 .whatwaf 隐藏目录
                shutil.rmtree(HOME)
                info("home folder removed")
            except KeyboardInterrupt:
                fatal("cleaning aborted")
            except OSError:
                fatal("no home folder detected, already cleaned?")
            exit(0)

        # 初始化 sqlite3 数据库， 创建~/.whatwaf/whatwaf.sqlite
        # 如果没有 cached_payloads 或者 cached_urls 表，就创建，否则跳过， 然后函数 return 一个 cursor 指针操作数据库的
        cursor = initialize()

        # 如果指定了 --export FILE-TYPE 选项
        # 这里只导出 cached_payloads 表中的数据
        if opts.exportEncodedToFile is not None:
            # fetch_data(cursor, table_name=None)
            # return 一个列表, 包含一行一行的数据， 然后列表里面镶嵌着 每一列的元组
            payloads = fetch_data(cursor, table_name='cached_payloads')
            if len(payloads) != 0:
                # export_payloads() 把 payload 列的数据写入文件，然后返回这个文件的 filename
                exported_payloads_path = export_payloads(payloads, opts.exportEncodedToFile)

                success("payloads exported to: {}".format(exported_payloads_path))
            else:
                # 数据库里面没有数据
                warning("there appears to be no payloads stored in the database, to create payloads use the "
                        "following options:")
                proc = subprocess.check_output(["python", "whatwaf.py", "--help"])
                parsed_help = CmdLineParser.parse_help_menu(str(proc), "encoding options:", "output options:")
                print(parsed_help)
                exit(1)

        # 如果指定了 -vC --view-cache， 这个选项展示 cached_payload 和 cached_url 两张表的内容
        if opts.viewAllCache:
            cached_payloads = fetch_data(cursor, table_name='cached_payloads')
            cached_urls = fetch_data(cursor, table_name='cached_urls')

            # 其实就是将 cached_payload 和 cached_url 两个表的数据 全部展示， 把他们展示的漂亮点而已
            display_cached(cached_urls, cached_payloads)
            exit(0)

        # 指定了　-pC --payload-cache, 这个选项仅仅只展示 cached_payload 表的内容
        if opts.viewCachedPayloads:
            payloads = fetch_data(cursor, table_name='cached_payloads')
            if len(payloads) != 0:
                display_cached(None, payloads)
            else:
                warning("there appears to be no payloads stored in the database, to create payloads use the"
                        " following options:")
                proc = subprocess.check_output(["python", "whatwaf.py", "--help"])
                parsed_help = CmdLineParser.parse_help_menu(proc, "encoding options:", "output options:")
                print(parsed_help)
            exit(0)

        # 指定了　-uC --view-url-cache, 这个选项仅仅只展示 cached_url 表的内容
        if opts.viewUrlCache:
            cached_urls = fetch_data(cursor, table_name='cached_urls')
            display_cached(cached_urls, None)
            exit(0)

        # 指定了 -e --encode
        # -e PAYLOAD [TAMPER-SCRIPT-LOAD-PATH ...], --encode PAYLOAD [TAMPER-SCRIPT-LOAD-PATH ...]
        # 这个地方 没有说 要如何指定 payload 和 payload 的路径, 先丢着
        if opts.encodePayload is not None:
            payload = opts.encodePayload[0]
            # opt.encodePayload[1:] -> payload 的加载路径, 例如 tampers.lowlevelunicodecharencode
            load_path = opts.encodePayload[1:]
            # 有可能加载好几个 payload 路径
            payload_list = []
            for load in load_path:
                try:
                    # encode(payload, script) 参数, script 应该就是 payload 位置参数
                    # eccode() 函数返回的是 根据 payload 产生的 绕过 字符串
                    payload = encode(payload, load)
                    payload_list.append(payload)
                except (AttributeError, ImportError):
                    warning("invalid load path given: '{}', skipping it and continuing".format(load))

            success("encoded successfully:")
            print spacer
            result = False
            for i, payload in enumerate(payload_list):
                # 上面得到 encoded successfully 之后，就把 payload 写入 database
                result = insert_payload(payload, cursor)
                print "{}{}".format(
                    colored("#" + str(i) + " ", 'white'),
                    payload
                )
            print spacer

            if result:
                info("payload has been cached for future use")
                exit(0)
            else:
                fatal("payload throwing error, see below")
                print colored(result, 'red')
                exit(1)

        # 指定 -el --encode-list 指定 payload 文件， payload 要用一行一行的隔开
        # -el PATH TAMPER-SCRIPT-LOAD-PATH, --encode-list PATH TAMPER-SCRIPT-LOAD-PATH
        if opts.encodePayloadList is not None:
            try:
                file_path, load_path = opts.encodePayloadList
                info("encoding payloads from given file '{}' using given tamper '{}'".format(
                    colored(file_path, 'white'),
                    colored(load_path, 'white')
                ))

                with open(file_path) as payloads:
                    # encode(payload, tamper_path)
                    encoded = [encode(p.strip(), load_path) for p in payloads.readlines()]

                    # 如果指定了　--save FILENAME
                    if opts.saveEncodedPayloads is not None:
                        with open(opts.saveEncodedPayloads, "a+") as save:
                            for item in encoded:
                                save.write(item + "\n")
                        success("saved encoded payloads to file '{}' successfully".format(opts.saveEncodedPayloads))
                    else:
                        success("payloads encoded successfully:")
                        print(spacer)
                        for i, item in enumerate(encoded, start=1):
                            # 写入数据库
                            insert_payload(item, cursor)
                            print("{} {}".format(colored("#" + str(i), 'white'), item))
                        print(spacer)
                info("payloads have been cached for future use")
            except IOError:
                fatal("provided file '{}' appears to not exist, check the path and try again".format(file_path))
            except (AttributeError, ImportError):
                fatal("invalid load path given, check the load path and try again")
            exit(0)

        # 暂时先屏蔽
        # 指定了 --update
        # if opts.updateWhatWaf:
        #     info("update in progress")
        #     cmd = shlex.split("git pull origin master")
        #     subprocess.call(cmd)
        #     exit(0)

        # 指定了 --tampers
        # 这个 options 的命令是 列出所有的 tamper 可用列表
        if opts.listEncodingTechniques:
            info("gathering available tamper script load paths")
            # 返回的是所有的 tamper 的名字的集合 -> set()
            # is_tampers=True 就是返回 tampers 目录下的所有 tamper 名字集合
            # is_wafs=True 就是返回 plugins 目录下的所有 plugin 名字的集合

            print spacer
            tamper_list = get_encoding_list(TAMPERS_DIRECTORY, is_tampers=True, is_wafs=False)
            for tamper in sorted(tamper_list):
                print(tamper)
            print spacer
            exit(0)

        # 指定了 --wafs
        # 列出所有的 plugins 目录下的所有的 列表
        if opts.viewPossibleWafs:
            import importlib

            info("gathering a list of possible detectable wafs")

            print spacer
            wafs_list = get_encoding_list(PLUGINS_DIRECTORY, is_tampers=False, is_wafs=True)
            for i, waf in enumerate(wafs_list, start=1):
                try:
                    imported = importlib.import_module(waf)
                    print("{}".format(imported.__product__))
                except ImportError:
                    pass
            print spacer
            exit(0)

        # 在运行大型扫面之前先检查 更新, 先暂时关闭
        # gotta find a better way to check for updates so im a hotfix it
        # info("checking for updates")
        # check_version()

        # -Y --yaml sendToYAML
        # -C --cvs sendToCSV
        # -J --json sendToJSON
        format_opts = [opts.sendToYAML, opts.sendToCSV, opts.sendToJSON]
        # 指定了 -F --format
        if opts.formatOutput:
            amount_used = 0
            for item in format_opts:
                if item is True:
                    amount_used += 1
            if amount_used > 1:
                warning(
                    "multiple file formats have been detected, there is a high probability that this will cause "
                    "issues while saving file information. please use only one format at a time"
                )
            elif amount_used == 0:
                warning(
                    "output will not be saved to a file as no file format was provided. to save output to file "
                    "pass one of the file format flags (eg `-J` for JSON format)"
                )
        elif any(format_opts) and not opts.formatOutput:
            warning(
                "you've chosen to send the output to a file, but have not formatted the output, no file will be saved "
                "do so by passing the format flag (eg `-F -J` for JSON format)"
            )

        # 指定了 --skip skipBypassChecks 和 --tamper-int amountOfTampersToDisplay
        if opts.skipBypassChecks and opts.amountOfTampersToDisplay is not None:
            warning(
                "you've chosen to skip bypass checks and chosen an amount of tamper to display, tampers will be skipped"
            )

        # there is an extra dependency that you need in order
        # for requests to run behind socks proxies, we'll just
        # do a little check to make sure you have it installed
        # --tor     opt.runBehindTor
        # --proxy   opt.runBehindProxy
        # --tor --proxy 不为空 and socks in opt.runBehindProxy
        # 如果指定了 --tor --proxy --proxy 必须为 sock 就导入 socks 模块
        if opts.runBehindTor or opts.runBehindProxy is not None and "socks" in opts.runBehindProxy:
            try:
                import socks
            except ImportError:
                # if you don't we will go ahead and exit the system with an error message
                error(
                    "to run behind socks proxies (like Tor) you need to install pysocks `pip install pysocks`, "
                    "otherwise use a different proxy protocol"
                )
                sys.exit(1)

        # configure_request_headers(user_agent=None, proxy=None, random_agent=False, tor=None, tor_port=9050)
        # return proxy, user_agent
        # configure_request_headers 判断如果没有指定 --proxy 会出现警告信息, 但是不会出错
        # 配置请求头和User Agent, 检查是否符合规范的, 符合的会返回 proxy 和 user_agent
        proxy, user_agent = configure_request_headers(
            # opts.usePersonalAgent -pa
            user_agent=opts.usePersonalAgent,
            # opts.runBehindProxy --proxy
            proxy=opts.runBehindProxy,
            # opts.useRandomAgent -ra 从 whatwaf/content/data/user_agents.txt 中随机挑选一个作为 USER_AGENT 客户请求头
            random_agent=opts.useRandomAgent,
            # opt.runBehindTor --tor, tor 默认是 socket5://127.0.0.1:9050,
            # 所以如果要指定使用 tor 代理, 直接 --tor 用默认的即可
            tor=opts.runBehindTor,
            # opt.configTorPort -tP --tor-port default=9050
            tor_port=opts.configTorPort
        )

        # 这个要先丢着
        # 如果指定了 --tor 就根据 https://check.torproject.org response返回的信息确定是否启用了 Tor
        # if opts.runBehindTor:
        #     import re
        #
        #     info("checking Tor connection")
        #     check_url = "https://check.torproject.org/"
        #     check_regex = re.compile("This browser is configured to use Tor.", re.I)
        #
        #     # 这里没判断,如果没有指定 --proxy 应该是要报错的
        #     # get_page() 是使用request 模块请求, BeautifulSoup 解析的
        #     _, _, content, _ = get_page(check_url, proxy=proxy, user_agent=user_agent)
        #
        #     if check_regex.search(str(content)) is not None:
        #         success("it appears that Tor is working properly")
        #     else:
        #         warning("it appears Tor is not configured properly")

        # 指定 -p --payload
        # 直说要使用 payload, 却没有说明如何使用 payload 用哪些payload
        if opts.providedPayloads is not None:
            # 如果指定了多个 payload 就丢入 payload_list 列表
            # 支持输入多个 payload 用逗号隔开存入 payload_list
            payload_list = [p.strip() if p[0] == " " else p for p in str(opts.providedPayloads).split(",")]
            info("using provided payloads")
        elif opts.payloadList is not None:
            # 如果指定了 payload list 文件
            # --pl PAYLOAD-LIST-PATH
            try:
                open(opts.payloadList).close()
            except:
                fatal("provided file '{}' does not exists, check the path and try again".format(opts.payloadList))
                exit(1)
            payload_list = [p.strip("\n") for p in open(opts.payloadList).readlines()]
            info("using provided payload file '{}'".format(opts.payloadList))
        else:
            # 如果都没有指定, 就使用默认的 whatwaf/content/data/default_payloads.lst 文件
            payload_list = WAF_REQUEST_DETECTION_PAYLOADS
            info("using default payloads")

        # 如果指定了 verbose
        if opts.runInVerbose:
            for payload in payload_list:
                info("using payload: {}".format(payload))

        # 指定了 --fingerprint 会保存指纹
        if opts.saveFingerprints:
            warning(
                "fingerprinting is enabled, all fingerprints (WAF related or not) will be saved for further analysis "
                "if the fingerprint already exists it will be skipped"
            )

        # 指定了 --traffic FILENAME
        if opts.trafficFile is not None:
            info("saving HTTP traffic to '{}'".format(opts.trafficFile))
        # 指定了 --throttle INT, default 0
        if opts.sleepTimeThrottle != 0:
            info("sleep throttle has been set to {}s".format(opts.sleepTimeThrottle))

        try:
            if opts.postRequest:
                request_type = "POST"
            else:
                request_type = "GET"

            request_count = 0

            # -u --url
            if opts.runSingleWebsite:
                # opt.forceSSL --force-ssl
                # normalization_url(url, ssl=False) -> 是实现自动添加 http 或者 https 头的
                url_to_use = normalization_url(opts.runSingleWebsite, ssl=opts.forceSSL)

                # 在指定了 -u 的前提下, 指定 -c --url-cache default=False, 默认检查
                # if opts.checkCachedUrls:

                # check_url_against_cached(url, cursor) 如果 cached_urls 表里面有 给的 url 参数的话,
                # 就返回这个 url 在数据库中的数据行, 如果没有就是返回 Null
                checked_results = check_url_cached(url_to_use, cursor)

                # 如果数据库里面有
                if checked_results is not None:
                    print(RESULTS_TEMPLATE.format(
                        spacer,
                        # uri
                        str(checked_results[1]),
                        # Identified Protections
                        str(checked_results[2]),
                        # Identified Tampers
                        str(checked_results[3]),
                        # Identified Web Server
                        str(checked_results[4]),
                        spacer
                    ))
                    exit(0)

                # 在指定了 -u 的前提下, 指定 -T --test default = True, 默认 去测试, 不用特意指定
                # if opts.testTargetConnection:
                info("testing connection to target URL before starting attack")
                # opt.extraHeaders -H --headers 注意这个headers要字典类型
                # 给参数的时候要形如这样的:
                # --headers {"Content-Length": "23", "User-Agent": "python-requests/2.10.0"}
                results = test_target_connection(
                    url=url_to_use, post_data=opts.postRequestData, proxy=proxy, user_agent=user_agent,
                    headers=opts.extraHeaders
                )
                if results == "nogo":
                    fatal("connection to target URL failed multiple times, check connection and try again")
                    exit(1)
                elif results == "acceptable":
                    warning(
                        "there appears to be some latency on the connection, this may interfere with results"
                    )
                else:
                    success("connection succeeded, continuing")

                info("running single web application '{}'".format(url_to_use))

                # 指定了 -u 然后发送请求, detection_main 是主请求函数
                # detection_main(url, payload_list, cursor, **kwargs)
                # detection_main 返回 response_count 总请求的数量
                amount_of_requests = detection_main(
                    url_to_use, payload_list, cursor,
                    request_type=request_type,
                    post_data=opts.postRequestData,
                    user_agent=user_agent,
                    # --headers 后面要跟字典参数
                    provided_headers=opts.extraHeaders,
                    proxy=proxy,
                    verbose=opts.runInVerbose,
                    skip_bypass_check=opts.skipBypassChecks,
                    # verifyNumber --verify-num INT
                    verification_number=opts.verifyNumber,
                    # --fingerprint
                    # fingerprint_waf=opts.saveFingerprints,
                    formatted=opts.formatOutput,
                    # --tamper-int INT
                    tamper_int=opts.amountOfTampersToDisplay,
                    use_json=opts.sendToJSON,
                    use_yaml=opts.sendToYAML,
                    use_csv=opts.sendToCSV,
                    # --traffic FILENAME
                    traffic_file=opts.trafficFile,
                    throttle=opts.sleepTimeThrottle,
                    request_timeout=opts.requestTimeout,
                    # -W --determine-webserver default=False
                    # 这个应该默认开启
                    # determine_server=opts.determineWebServer,
                    # 线程数
                    threaded=opts.threaded,
                    #  --force-file default=False
                    force_file_creation=opts.forceFileCreation,
                    # -o --output
                    save_file_copy_path=opts.outputDirectory
                )

                request_count = amount_of_requests if amount_of_requests is not None else request_count

            elif any(o is not None for o in [opts.runMultipleWebsites, opts.burpRequestFile]):
                # 如果不指定 -u 而是指定了 -l --list 或者 --burp FILE-PATH
                info("reading from '{}'".format(opts.runMultipleWebsites or opts.burpRequestFile))

                try:
                    open(opts.runMultipleWebsites or opts.burpRequestFile)
                except IOError:
                    fatal("file: '{}' did not open, does it exist?".format(opts.runMultipleWebsites))
                    exit(-1)

                if opts.runMultipleWebsites is not None:
                    # 需要检测的 url 列表
                    site_runners = []

                    with open(opts.runMultipleWebsites) as urls:
                        for url in urls:
                            possible_url = normalization_url(url.strip(), ssl=opts.forceSSL)

                            if opts.checkCachedUrls:
                                url_is_cached = check_url_cached(possible_url, cursor)

                                if url_is_cached is not None:
                                    # 数据库里面有
                                    print(
                                        RESULTS_TEMPLATE.format(
                                            "-" * 20,
                                            str(url_is_cached[1]),
                                            str(url_is_cached[2]),
                                            str(url_is_cached[3]),
                                            str(url_is_cached[4]),
                                            "-" * 20
                                        )
                                    )

                                else:
                                    site_runners.append(possible_url)
                            else:
                                site_runners.append(possible_url)
                elif opts.burpRequestFile is not None:
                    # parse_burp_request return: retval -> 包含 url 的列表
                    site_runners = parse_burp_request(opts.burpRequestFile)
                else:
                    site_runners = []

                if len(site_runners) == 0:
                    fatal("no targets parsed from file, exiting")
                    exit(1)
                else:
                    info("parsed a total of {} target(s) from file".format(len(site_runners)))

                for i, url in enumerate(site_runners, start=1):
                    if opts.testTargetConnection:
                        info("testing connection to target URL before starting attack")
                        results = test_target_connection(url, proxy=proxy, user_agent=user_agent, headers=opts.extraHeaders)
                        if results == "nogo":
                            fatal("connection to target URL failed multiple times, check connection and try again")
                            exit(1)
                        elif results == "acceptable":
                            warning(
                                "there appears to be some latency on the connection, this may interfere with results"
                            )
                        else:
                            success("connection succeeded, continuing")

                    info("currently running on site #{} ('{}')".format(i, url))
                    requests = detection_main(
                        url, payload_list, cursor, user_agent=user_agent, proxy=proxy,
                        verbose=opts.runInVerbose, skip_bypass_check=opts.skipBypassChecks,
                        verification_number=opts.verifyNumber, formatted=opts.formatOutput,
                        tamper_int=opts.amountOfTampersToDisplay, use_json=opts.sendToJSON,
                        use_yaml=opts.sendToYAML, use_csv=opts.sendToCSV,
                        # fingerprint_waf=opts.saveFingerprints,
                        provided_headers=opts.extraHeaders,
                        traffic_file=opts.trafficFile, throttle=opts.sleepTimeThrottle,
                        request_timeout=opts.requestTimeout, post_data=opts.postRequestData,
                        request_type=request_type,
                        # check_server=opts.determineWebServer,
                        threaded=opts.threaded, force_file_creation=opts.forceFileCreation,
                        save_file_copy_path=opts.outputDirectory
                    )
                    request_count = request_count + requests if requests is not None else request_count
                    print("\n\b")
                    time.sleep(0.5)

            if request_count != 0:
                info("total requests sent: {}".format(request_count))
            else:
                warning("request counter failed to count correctly, deactivating")

        except KeyboardInterrupt:
            fatal("user aborted scanning")
        except InvalidURLProvided:
            fatal(
                "the provided URL is unable to be validated, check the URL and try again (you may need to unquote the "
                "HTML entities)"
            )
        except Exception as e:
            # traceback 是跟踪堆栈的
            import traceback

            sep = colored("-" * 30, 'white')

            fatal("WhatWaf has caught an unhandled exception with the error message: '{}'.".format(str(e)))

            exception_data = "Traceback (most recent call):\n{}{}".format(
                "".join(traceback.format_tb(sys.exc_info()[2])), str(e)
            )

            error("\n{}\n{}\n{}".format(sep, exception_data, sep))

            request_issue_creation(exception_data)


if __name__ == "__main__":
    main()
