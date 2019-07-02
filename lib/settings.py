# encoding: utf8
import os
import re
import termcolor

# version number <major>.<minor>.<commit>
VERSION = "1.4.5"

# version string
VERSION_TYPE = "($dev)" if VERSION.count(".") > 1 else "($stable)"

# cool looking banner
BANNER = """
                              ,------.
                             '  .--.  '
    ,--.   .--.   ,--.   .--.|  |  |  |
    |  |   |  |   |  |   |  |'--'  |  |
    |  |   |  |   |  |   |  |    __.  |
    |  |.'.|  |   |  |.'.|  |   |   .'
    |         |   |         |   |___|
    |   ,'.   |hat|   ,'.   |af .---.
    '--'   '--'   '--'   '--'   '---'
"/><script>alert("WhatWaf?<|>v{}{}");</script>
""".format(VERSION, VERSION_TYPE)
BANNER = termcolor.colored(BANNER, 'cyan')

# current root working directory
ROOT_DIR = os.getcwd()

# template for the results if needed
RESULTS_TEMPLATE = "{}\nSite: {}\nIdentified Protections: {}\nIdentified Tampers: {}\nIdentified Webserver: {}\n{}"

# directory to do the importing for the WAF scripts
PLUGINS_IMPORT_TEMPLATE = "plugins.{}"

# directory to do the importing for the tamper scripts
TAMPERS_IMPORT_TEMPLATE = "tampers.{}"

# link to the create a new issue page
ISSUES_LINK = "https://github.com/Ekultek/WhatWaf/issues/new"

# regex to detect the URL protocol (http or https)
PROTOCOL_DETECTION = re.compile("http(s)?")

# check if a query is in a URL or not
URL_QUERY_REGEX = re.compile(r"(.*)[?|#](.*){1}\=(.*)")

# plugins (waf scripts) path
PLUGINS_DIRECTORY = "{}/plugins".format(ROOT_DIR)

# tampers (tamper scripts) path
TAMPERS_DIRECTORY = "{}/tampers".format(ROOT_DIR)

# name provided to unknown firewalls
UNKNOWN_FIREWALL_NAME = "Unknown Firewall"

# path to our home directory we want to storage to
HOME = "{}/.whatwaf".format(os.path.expanduser("~"))

# fingerprint path for unknown firewalls
UNKNOWN_PROTECTION_FINGERPRINT_PATH = "{}/fingerprints".format(HOME)

# JSON data file path
JSON_FILE_PATH = "{}/json_output".format(HOME)

# YAML data file path
YAML_FILE_PATH = "{}/yaml_output".format(HOME)

# CSV data file path
CSV_FILE_PATH = "{}/csv_output".format(HOME)

# for when an issue occurs but is not processed due to an error
UNPROCESSED_ISSUES_PATH = "{}/unprocessed_issues".format(HOME)

# request token path
TOKEN_PATH = "{}/data/key/auth.key".format(ROOT_DIR)

# known POST strings (I'll probably think of more later)
POST_STRING_NAMES_PATH = "{}/data/lst/post_strings.lst".format(ROOT_DIR)

# path to the database file
DATABASE_FILENAME = "{}/whatwaf.sqlite".format(HOME)

# payloads that have been exported from database cache
EXPORTED_PAYLOADS_PATH = "{}/payload_exports".format(HOME)

# default payloads path
DEFAULT_PAYLOAD_PATH = "{}/data/lst/default_payloads.lst".format(ROOT_DIR)

# arguments that need to be blocked from issue creations and waf creations
SENSITIVE_ARGUMENTS = ("--proxy", "-u", "--url", "-D", "--data", "--pa", "-b", "--burp")

# payloads for detecting the WAF, at least one of
# these payloads `should` trigger the WAF and provide
# us with the information we need to identify what
# the WAF is, along with the information we will need
# to identify what tampering method we should use
# they are located in ./content/data/default_payloads.lst
WAF_REQUEST_DETECTION_PAYLOADS = [p.strip() for p in open(DEFAULT_PAYLOAD_PATH).readlines()]

# random home pages to try and get cookies
RAND_HOMEPAGES = (
    "index.php", "index.exe", "index.html", "index.py", "index.pl", "index.exe",
    "phpadmin.php", "home.php", "home.html", "home.py", "home.pl", "home.exe",
    "phpcmd.exe", "index.phpcmd.exe", "index.html", "index.htm", "index.shtml",
    "index.php", "index.php5", "index.php5.exe", "index.php4.exe", "index.php4",
    "index.php3", "index.cgi", "default.html", "default.htm", "home.html", "home.htm",
    "Index.html", "Index.htm", "Index.shtml", "Index.php", "Index.cgi", "Default.html",
    "Default.htm", "Home.html", "Home.htm", "placeholder.html"
)

# this is a regex to validate a URL. It was taken from Django's URL validation technique
# reference can be found here:
# `https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not/7160778#7160778`
URL_VALIDATION = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)
