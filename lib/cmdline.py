# encoding: utf8
from argparse import ArgumentParser, Action


class StoreDictKeyPairs(Action):
    """
    custom action to create a dict from a provided string in the format of key=value or key:value
    """

    retval = {}

    def __call__(self, parser, namespace, values, option_string=None):
        # discover what we split by
        """
        保存 cmd 中 dic 参数
        :param parser:
        :param namespace:
        :param values:
        :param option_string:
        :return:
        """
        for kv in values.split(","):
            if ":" in kv:
                splitter = ":"
            else:
                splitter = "="
            if kv.count(splitter) != 1:
                first_equal_index = kv.index(splitter)
                key = kv[:first_equal_index].strip()
                value = kv[first_equal_index + 1:].strip()
                self.retval[key] = value
            else:
                k, v = kv.split(splitter)
                self.retval[k.strip()] = v.strip()
        # return the attribute as {'foo': 'bar'}
        setattr(namespace, self.dest, self.retval)


class CmdLineParser(ArgumentParser):
    def __init__(self):
        super(CmdLineParser, self).__init__()

    @staticmethod
    def cmd_parser(get_help=False):
        """
        # prog 程序的名字，默认 sys.argv[0]
        # usage -> 描述程序的用法，默认是展示options的描述

        :return: 返回 argparser 的 opts object
        """

        # apparently Python 3.x doesn't like it when there's a '%' in the string
        # this will cause some issues, more specifically a `TypeError` because it's trying
        # to format the string. so the simplest solution for the problem? remove the '%'
        # sign from the string. because Python 3.x likes to be as difficult and ridiculous
        # as it possibly can.
        parser = ArgumentParser(prog="whatwaf.py", add_help=True, usage=(
            "./whatwaf.py [options] [arguments]"
        ))

        # helper argument
        # helper = parser.add_argument_group('optional arguments')
        # helper.add_argument('-h', '--help', desc='show this help message and exit', action='help')

        # mandatory argument
        mandatory = parser.add_argument_group("mandatory arguments",
                                              "arguments that have to be passed for the program to run")
        mandatory.add_argument("-u", "--url", dest="runSingleWebsite", metavar="URL",
                               help="Pass a single URL to detect the protection")
        mandatory.add_argument("-l", "--list", "-f", "--file", dest="runMultipleWebsites",
                               metavar="PATH", default=None,
                               help="Pass a file containing URL's (one per line) to detect the protection")
        mandatory.add_argument("-b", "--burp", dest="burpRequestFile", metavar="FILE-PATH", default=None,
                               help="Pass a Burp Suite request file to perform WAF evaluation")

        # request argument
        req_args = parser.add_argument_group("request arguments",
                                             "arguments that will control your requests")
        req_args.add_argument("--pa", dest="usePersonalAgent", metavar="USER-AGENT",
                              help="Provide your own personal agent to use it for the HTTP requests")
        req_args.add_argument("--ra", dest="useRandomAgent", action="store_true",
                              help="Use a random user-agent for the HTTP requests")
        req_args.add_argument("-H", "--headers", dest="extraHeaders", action=StoreDictKeyPairs,
                              metavar="HEADER=VALUE,HEADER:VALUE..",
                              help="Add your own custom headers to the request. To use multiple "
                                   "separate headers by comma. Your headers need to be exact"
                                   "(IE: Set-Cookie=a345ddsswe,X-Forwarded-For:127.0.0.1)")
        req_args.add_argument("--proxy", dest="runBehindProxy", metavar="PROXY",
                              help="Provide a proxy to run behind in the format "
                                   "type://address:port (eg socks5://10.54.127.4:1080")
        req_args.add_argument("--tor", dest="runBehindTor", action="store_true",
                              help="Use Tor as the proxy to run behind, must have Tor installed")
        # 默认带上, 没必要特意带上
        # req_args.add_argument("--check-tor", dest="checkTorConnection", action="store_true",
        #                       help="Check your Tor connection")
        req_args.add_argument("-p", "--payloads", dest="providedPayloads", metavar="PAYLOADS",
                              help="Provide your own payloads separated by a comma IE AND 1=1,AND 2=2")
        req_args.add_argument("--pl", dest="payloadList", metavar="PAYLOAD-LIST-PATH",
                              help="Provide a file containing a list of payloads 1 per line")
        req_args.add_argument("--force-ssl", dest="forceSSL", action="store_true",
                              help="Force the assignment of HTTPS instead of HTTP while processing "
                                   "(*default=HTTP unless otherwise specified by URL)")
        req_args.add_argument("--throttle", dest="sleepTimeThrottle", type=int, metavar="THROTTLE-TIME (seconds)",
                              default=0, help="Provide a sleep time per request (*default=0)")
        req_args.add_argument("--timeout", dest="requestTimeout", type=int, metavar="TIMEOUT", default=15,
                              help="Control the timeout time of the requests (*default=15)")
        req_args.add_argument("-P", "--post", dest="postRequest", action="store_true",
                              help="Send a POST request (*default=GET)")
        req_args.add_argument("-D", "--data", dest="postRequestData", metavar="POST-STRING",
                              help="Send this data with the POST request "
                                   "(IE password=123&name=Josh *default=random)")
        req_args.add_argument("-t", "--threaded", dest="threaded",  metavar="threaded",  type=int,
                              help="Send requests in parallel (specify number of threads *default=1)")
        req_args.add_argument("-tP", "--tor-port", type=int, default=9050, dest="configTorPort",
                              help="Change the port that Tor runs on (*default=9050)")
        # 默认带上, 没必要特意带上
        # req_args.add_argument("-T", "--test", dest="testTargetConnection", default=True, action="store_false",
        #                       help="Test the connection to the website before starting (default is True)")

        # encoding argument 组
        encoding_opts = parser.add_argument_group("encoding options",
                                                  "arguments that control the encoding of payloads")
        encoding_opts.add_argument("-e", "--encode",
                                   dest="encodePayload", nargs="+", metavar=("PAYLOAD", "TAMPER-SCRIPT-LOAD-PATH"),
                                   help="Encode a provided payload using provided tamper script(s) "
                                        "you are able to payy multiple tamper script load paths to "
                                        "this argument and the payload will be tampered as requested")
        encoding_opts.add_argument("-el", "--encode-list",
                                   dest="encodePayloadList",
                                   nargs=2,
                                   metavar=("PATH", "TAMPER-SCRIPT-LOAD-PATH"),
                                   help="Encode a file containing payloads (one per line) "
                                        "by passing the path and load path, data can only "
                                        "encoded using a single tamper script load path")

        # output argument 组
        output_opts = parser.add_argument_group("output options",
                                                "arguments that control how WhatWaf handles output")
        output_opts.add_argument("-F", "--format", action="store_true", dest="formatOutput",
                                 help="Format the output into a dict and display it")
        output_opts.add_argument("-J", "--json", action="store_true", dest="sendToJSON",
                                 help="Send the output to a JSON file")
        output_opts.add_argument("-Y", "--yaml", action="store_true", dest="sendToYAML",
                                 help="Send the output to a YAML file")
        output_opts.add_argument("-C", "--csv", action="store_true", dest="sendToCSV",
                                 help="Send the output to a CSV file")
        output_opts.add_argument("--fingerprint", action="store_true", dest="saveFingerprints",
                                 help="Save all fingerprints for further investigation")
        output_opts.add_argument("--tamper-int", metavar="INT", dest="amountOfTampersToDisplay", type=int,
                                 default=5, help="Control the amount of tampers that are displayed (*default=5)")
        output_opts.add_argument("--traffic", metavar="FILENAME", dest="trafficFile",
                                 help="store all HTTP traffic headers into a file of your choice")
        output_opts.add_argument("--force-file", action="store_true", default=False, dest="forceFileCreation",
                                 help="Force the creation of a file even if there is no protection identified")
        output_opts.add_argument("-o", "--output", metavar="DIR", dest="outputDirectory", default=None,
                                 help="Save a copy of the file to an arbitrary directory")

        # database argument 组
        database_arguments = parser.add_argument_group("database arguments",
                                                       "arguments that pertain to Whatwafs database")
        # 默认带上, 没必要特意指定
        # database_arguments.add_argument(
        #     "-c", "--url-cache", default=False, action="store_true", dest="checkCachedUrls",
        #     help="Check against URL's that have already been cached into the database before running them "
        #          "saves some time on scanning multiple (*default=False)"
        # )
        database_arguments.add_argument(
            "-uC", "--view-url-cache", default=False, action="store_true", dest="viewUrlCache",
            help="Display all the URL cache inside of the database, this includes the netlock, "
                 "tamper scipts, webserver, and identified protections"
        )
        database_arguments.add_argument(
            "-pC", "--payload-cache", action="store_true", default=False, dest="viewCachedPayloads",
            help="View all payloads that have been cached inside of the database"
        )
        database_arguments.add_argument(
            "-vC", "--view-cache", action="store_true", default=False, dest="viewAllCache",
            help="View all the cache in the database, everything from URLs to payloads"
        )
        database_arguments.add_argument(
            "--export", metavar="FILE-TYPE", default=None, dest="exportEncodedToFile",
            choices=["txt", "text", "json", "csv", "yaml", "yml"],
            help="Export the already encoded payloads to a specified file type and save them "
                 "under the home(~/.whatwaf) directory"
        )

        # misc argument 组
        misc = parser.add_argument_group("misc arguments",
                                         "arguments that don't fit in any other category")
        misc.add_argument("--verbose", dest="runInVerbose", action="store_true",
                          help="Run in verbose mode (more output)")
        misc.add_argument("--update", dest="updateWhatWaf", action="store_true",
                          help="Update WhatWaf to the newest development version")
        misc.add_argument("--save", dest="saveEncodedPayloads", metavar="FILENAME",
                          help="Save the encoded payloads into a file")
        misc.add_argument("--skip", dest="skipBypassChecks", action="store_true",
                          help="Skip checking for bypasses and just identify the firewall")
        misc.add_argument("--verify-num", dest="verifyNumber", metavar="INT", type=int,
                          help="Change the request amount to verify if there really is not a WAF present"
                               "(*default=5)")
        misc.add_argument("-W", "--determine-webserver", action="store_true", default=False, dest="determineWebServer",
                          help="Attempt to determine what web server is running on the backend "
                               "(IE Apache, Nginx, etc.. *default=False)")
        misc.add_argument("--wafs", action="store_true", default=False, dest="viewPossibleWafs",
                          help="Output a list of possible firewalls that can be detected by this program")
        misc.add_argument("--tampers", action="store_true", dest="listEncodingTechniques",
                          help="Output a list of usable tamper script load paths")

        # hidden argument
        hidden = parser.add_argument_group()
        hidden.add_argument("--clean", action="store_true", dest="cleanHomeFolder",
                            help='Clean up WhatWaf home folders')

        opts = parser.parse_args()

        if get_help:
            return parser.print_help()
        else:
            return opts

    @staticmethod
    def parse_help_menu(data, start_field, end_field):
        """
        parse the help menu from a certain string to a certain string
        and return the parsed help
        将 help 中的文字截取出来

        :param data: cmd 中所有的 help 信息
        :param start_field: 以...子模块开头的块, 例如 -> encoding options:
        :param end_field: 以...子模块结束的块, 例如-> output options:
        :return:
        """

        try:
            start_index = data.index(start_field)
            end_index = data.index(end_field)
            retval = data[start_index:end_index].strip()
        except TypeError:
            # python3 is stupid and likes `bytes` because why tf not?
            plus = 60
            # so now we gotta dd 60 in order to get the last line from the last command
            # out of the way
            start_index = data.decode().index(start_field) + plus
            end_index = data.decode().index(end_field)
            # and then we gotta convert back
            data = str(data)
            # and then we gotta store into a temporary list
            tmp = data[start_index:end_index]
            # split the list into another list because of escapes
            # join that list with a new line and finally get the
            # retval out of it. Because that makes PERFECT sense
            retval = "\n".join(tmp.split("\\n"))
        return retval
