# encoding: utf8
import time
from termcolor import colored


def info(string):
    print "[{}] [{}] {}".format(
        colored(time.strftime("%H:%M:%S"), 'cyan'),
        colored("INFO", 'white'),
        string
    )


def debug(string):
    print "[{}] [{}] {}".format(
        colored(time.strftime("%H:%M:%S"), 'cyan'),
        colored("DEBUG", 'white'),
        string
    )


def warning(string):
    print "[{}] [{}] {}".format(
        colored(time.strftime("%H:%M:%S"), 'cyan'),
        colored('WARNING', 'yellow'),
        string
    )


def error(string):
    print "[{}] [{}] {}".format(
        colored(time.strftime("%H:%M:%S"), 'cyan'),
        colored("[ERROR]", 'red'),
        string
    )


def fatal(string):
    print "[{}] [{}] {}".format(
        colored(time.strftime("%H:%M:%S"), 'cyan'),
        colored("[FATAL]", 'red'),
        string
    )


def payload(string):
    print "[{}] [{}] {}".format(
        colored(time.strftime("%H:%M:%S"), 'cyan'),
        colored("PAYLOAD", 'blue'),
        string
    )


def success(string):
    print "[{}] [{}] {}".format(
        colored("{}".format(time.strftime("%H:%M:%S")), 'cyan'),
        colored("SUCCESS", 'green'),
        string
    )


def prompt(string, opts, default="n"):
    """
    获取用的输入,用于后面的交互

    :param string: 交互文字
    :param opts: 例如填入yN
    :param default: n
    :return: 返回用户的输入
    """

    opts = list(opts)
    # 原来的
    # choice = raw_input("\033[38m[{}]\033[0m[PROMPT] {}[{}]: ".format(
    #     time.strftime("%H:%M:%S"),
    #     string,
    #     "/".join(opts)
    # ))
    choice = raw_input("[{}] [{}] {}".format(
        colored(time.strftime("%H:%M:%S"), 'cyan'),
        colored('PROMPT', 'magenta'),
        string,
        "/".join(opts)
    ))

    if choice not in [o.lower() for o in opts]:
        choice = default
    return choice
