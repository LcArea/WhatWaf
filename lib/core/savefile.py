# encoding: utf8
from lib.print_format import warning, success, error, info
from lib.settings import UNKNOWN_PROTECTION_FINGERPRINT_PATH
import os
import json


def create_fingerprint(url, content_obj, status, headers, req_data=None, speak=False):
    """
    create the unknown firewall fingerprint file

    :param url: url
    :param content_obj: BeautifulSoup Object
    :param status: response.status_code
    :param headers: response.headers
    :param req_data: 请求方法 + url 形如 -> "GET https://example.org"
    :param speak: default False if speak=True, stdout "fingerprint saved to '{}'" information
    :return: 返回完整的 fingerprint 文件保存路径, 例如 -> ~/.whatwaf/fingerprinters/FILENAME
    """

    # UNKNOWN_PROTECTION_FINGERPRINT_PATH = "{}/fingerprints".format(HOME)
    # 为什么是指定了 --fingerprint 保存的路径却是 UNKNOW_PROTECTION_FINGERPRINT?
    if not os.path.exists(UNKNOWN_PROTECTION_FINGERPRINT_PATH):
        os.makedirs(UNKNOWN_PROTECTION_FINGERPRINT_PATH)

    __replace_http = lambda x: x.split("/")
    # 会把 url 中的请求方法给割掉 请求 http? 如果是 https 呢?
    __replace_specifics = lambda u: "http://{}".format(u.split("/")[2])

    try:
        # 假设原 url -> http://www.example.com/index?id=5
        # 返回形如 -> http://www.example.com
        url = __replace_specifics(url)
    except Exception:
        warning("full URL will be displayed to the public if an issue is created")
        url = url

    # 形如 <!--\n{}\nStatus code: {}\n{}\n-->\n{} 这里拼接的一样
    fingerprint = "<!--\n{}\nStatus code: {}\n{}\n-->\n{}".format(
        "GET {} HTTP/1.1".format(url) if req_data is None
        else
        "{} HTTP/1.1".format(req_data), str(status),
        '\n'.join("{}: {}".format(h, k) for h, k in headers.items()), str(content_obj)
    )

    # 形如 -> www.example.org 获取hostname
    filename = __replace_http(url)[2]
    # 不需要吧, 有些的域名就不用加 www
    # if "www" not in filename:
    #     filename = "www.{}".format(filename)

    full_file_path = "{}/{}".format(UNKNOWN_PROTECTION_FINGERPRINT_PATH, filename)

    if not os.path.exists(full_file_path):
        with open(full_file_path, "a+") as log:
            log.write(fingerprint)
        if speak:
            success("fingerprint saved to '{}'".format(full_file_path))
    # 返回完整的 fingerprint 文件保存路径
    return full_file_path


def write_to_file(filename, path, data, **kwargs):
    """
    write the data to a file

    :param filename:
    :param path:
    :param data:
    :param kwargs:
    :return:
    """

    write_yaml = kwargs.get("write_yaml", False)
    write_json = kwargs.get("write_json", False)
    write_csv = kwargs.get("write_csv", False)
    save_copy = kwargs.get("save_copy_to", None)

    full_path = "{}/{}".format(path, filename)

    if not os.path.exists(path):
        os.makedirs(path)
    if write_json and not write_yaml and not write_csv:
        with open(full_path, "a+") as _json:
            _json_data = json.loads(data)
            json.dump(_json_data, _json, sort_keys=True, indent=4)
    elif write_yaml and not write_json and not write_csv:
        try:
            # there is an extra dependency that needs to be installed for you to save to YAML
            # we'll check if you have it or not
            import yaml

            with open(full_path, "a+") as _yaml:
                _yaml_data = yaml.load(data)
                yaml.dump(_yaml_data, _yaml, default_flow_style=False)
        except ImportError:
            # if you don't we'll just skip the saving and warn you
            warning(
                "you do not have the needed dependency to save YAML data, to install the dependency run "
                "`pip install pyyaml`, skipping file writing"
            )
            return None
    elif write_csv and not write_json and not write_yaml:
        import csv

        _json_data = json.loads(data)
        try:
            csv_data = [
                ["url", "is_protected", "protection", "working_tampers"],
                [
                    _json_data["url"], _json_data["is protected"],
                    _json_data[
                        "identified firewall"
                    ] if _json_data["identified firewall"] is not None else "None",
                    _json_data[
                        "apparent working tampers"
                    ] if _json_data["apparent working tampers"] is not None else "None"
                ]
            ]
        except KeyError:
            pass
        with open(full_path, "a+") as _csv:
            writer = csv.writer(_csv)
            writer.writerows(csv_data)
    if save_copy is not None:
        import shutil
        try:
            shutil.copy(full_path, save_copy)
            info("copy of file saved to {}".format(save_copy))
        except Exception:
            error("failed to save copy of file, do you have permissions?")

    return full_path
