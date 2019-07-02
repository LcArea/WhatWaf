# encoding: utf8
from lib.settings import (
    VERSION,
    UNPROCESSED_ISSUES_PATH
)
from lib.core.request import random_string
from lib.print_format import warning

import os
import json
import requests
import re


def check_version(speak=True):
    """
    check the version number for updates
    """
    version_url = "https://raw.githubusercontent.com/Ekultek/WhatWaf/master/lib/settings.py"
    req = requests.get(version_url)
    content = req.text
    current_version = re.search("VERSION.=.(.......)?", content).group().split("=")[-1].strip().strip('"')
    my_version = VERSION
    if not current_version == my_version:
        if speak:
            warning("new version: {} is available".format(current_version))
        else:
            return False
    else:
        if not speak:
            return True


def save_temp_issue(data):
    """
    save unprocessed issues into a file so that they can be worked with later

    :param data: 形如 ->
        data = {
            "title": issue_title,
            "body": "WhatWaf version: `{}`\n"
                    "Running context: `{}`\n"
                    "Fingerprint:\n```\n{}\n```".format(
                        # full_fingerprint 就是 fingerprint 文件的里的所有内容
                        lib.settings.VERSION, data, full_fingerprint
            )
        }
    :return:
    """

    # UNPROCESSED_ISSUES_PATH = "{}/unprocessed_issues".format(HOME)
    if not os.path.exists(UNPROCESSED_ISSUES_PATH):
        os.makedirs(UNPROCESSED_ISSUES_PATH)
    file_path = "{}/{}.json".format(UNPROCESSED_ISSUES_PATH, random_string(length=32))
    with open(file_path, "a+") as outfile:
        json.dump(data, outfile)
    return file_path


