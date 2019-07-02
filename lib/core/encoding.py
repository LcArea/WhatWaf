# encoding: utf8
"""
This module aim to handle encoding options module when type whatwaf -h
"""
from lib.settings import TAMPERS_IMPORT_TEMPLATE
from lib.settings import PLUGINS_IMPORT_TEMPLATE
import importlib
import os


def get_encoding_list(directory, is_tampers=True, is_wafs=False):
    """
    get a quick simple list of encodings

    :param directory: directory you want to get
    :param is_tampers: get tampers list or plugins list?
    :param is_wafs: get tampers list or plugins list?
    :return: return a set() that contain tampers or plugins list
    """
    retval = set()
    items = os.listdir(directory)
    for item in items:
        if not any(skip in item for skip in ["__init__", "__pycache__"]):
            if is_tampers:
                item = TAMPERS_IMPORT_TEMPLATE.format(item.split(".")[0])
            elif is_wafs:
                if "unknown" not in item:
                    item = PLUGINS_IMPORT_TEMPLATE.format(item.split(".")[0])
            retval.add(item)
    return retval


def encode(payload, tamper_path):
    """
    encode the payload with the provided tamper

    :param payload: payload
    :param tamper_path: tamper path, eg -> tampers.lowlevelunicodecharencode
    :return: tamper之后的字符串
    """
    script = importlib.import_module(tamper_path)
    return script.tamper(payload)
