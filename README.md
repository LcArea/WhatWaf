# WhatWaf

## 概述
### Overview
WhatWaf 是一个高级的防火墙检测工具，用于检测当前Web url 或者 Web应用使用了什么Waf，通过特定的选项可以使用特定的 payload 绕过防火墙，剩下的靠自己去挖掘了

## 免责声明
### Disclaimer
此项目来源为 [https://github.com/Ekultek/WhatWaf](https://github.com/Ekultek/WhatWaf)

Origin sourc: [https://github.com/Ekultek/WhatWaf](https://github.com/Ekultek/WhatWaf)

出于学习的目的，在遵循源项目的开源协议的基础上修改整体架构，使其更加符合软件工程的规范，并且添加很多必要的注释，修复一些bug，原功能基本不变，只做一些更改, 更改的条目在 CHANGELOG 文件中

## 所有的选项以及说明
### Options
```
                              ,------.
                             '  .--.  '
    ,--.   .--.   ,--.   .--.|  |  |  |
    |  |   |  |   |  |   |  |'--'  |  |
    |  |   |  |   |  |   |  |    __.  |
    |  |.'.|  |   |  |.'.|  |   |   .'
    |         |   |         |   |___|
    |   ,'.   |hat|   ,'.   |af .---.
    '--'   '--'   '--'   '--'   '---'
"/><script>alert("WhatWaf?<|>v1.4.5($dev)");</script>

usage: ./whatwaf.py [options] [arguments]

optional arguments:
  -h, --help            show this help message and exit

mandatory arguments:
  arguments that have to be passed for the program to run

  -u URL, --url URL     Pass a single URL to detect the protection
  -l PATH, --list PATH, -f PATH, --file PATH
                        Pass a file containing URL's (one per line) to detect
                        the protection
  -b FILE-PATH, --burp FILE-PATH
                        Pass a Burp Suite request file to perform WAF
                        evaluation

request arguments:
  arguments that will control your requests

  --pa USER-AGENT       Provide your own personal agent to use it for the HTTP
                        requests
  --ra                  Use a random user-agent for the HTTP requests
  -H HEADER=VALUE,HEADER:VALUE.., --headers HEADER=VALUE,HEADER:VALUE..
                        Add your own custom headers to the request. To use
                        multiple separate headers by comma. Your headers need
                        to be exact(IE: Set-Cookie=a345ddsswe,X-Forwarded-
                        For:127.0.0.1)
  --proxy PROXY         Provide a proxy to run behind in the format
                        type://address:port (eg socks5://10.54.127.4:1080
  --tor                 Use Tor as the proxy to run behind, must have Tor
                        installed
  -p PAYLOADS, --payloads PAYLOADS
                        Provide your own payloads separated by a comma IE AND
                        1=1,AND 2=2
  --pl PAYLOAD-LIST-PATH
                        Provide a file containing a list of payloads 1 per
                        line
  --force-ssl           Force the assignment of HTTPS instead of HTTP while
                        processing (*default=HTTP unless otherwise specified
                        by URL)
  --throttle THROTTLE-TIME (seconds)
                        Provide a sleep time per request (*default=0)
  --timeout TIMEOUT     Control the timeout time of the requests (*default=15)
  -P, --post            Send a POST request (*default=GET)
  -D POST-STRING, --data POST-STRING
                        Send this data with the POST request (IE
                        password=123&name=Josh *default=random)
  -t threaded, --threaded threaded
                        Send requests in parallel (specify number of threads
                        *default=1)
  -tP CONFIGTORPORT, --tor-port CONFIGTORPORT
                        Change the port that Tor runs on (*default=9050)

encoding options:
  arguments that control the encoding of payloads

  -e PAYLOAD [TAMPER-SCRIPT-LOAD-PATH ...], --encode PAYLOAD [TAMPER-SCRIPT-LOAD-PATH ...]
                        Encode a provided payload using provided tamper
                        script(s) you are able to payy multiple tamper script
                        load paths to this argument and the payload will be
                        tampered as requested
  -el PATH TAMPER-SCRIPT-LOAD-PATH, --encode-list PATH TAMPER-SCRIPT-LOAD-PATH
                        Encode a file containing payloads (one per line) by
                        passing the path and load path, data can only encoded
                        using a single tamper script load path

output options:
  arguments that control how WhatWaf handles output

  -F, --format          Format the output into a dict and display it
  -J, --json            Send the output to a JSON file
  -Y, --yaml            Send the output to a YAML file
  -C, --csv             Send the output to a CSV file
  --fingerprint         Save all fingerprints for further investigation
  --tamper-int INT      Control the amount of tampers that are displayed
                        (*default=5)
  --traffic FILENAME    store all HTTP traffic headers into a file of your
                        choice
  --force-file          Force the creation of a file even if there is no
                        protection identified
  -o DIR, --output DIR  Save a copy of the file to an arbitrary directory

database arguments:
  arguments that pertain to Whatwafs database

  -uC, --view-url-cache
                        Display all the URL cache inside of the database, this
                        includes the netlock, tamper scipts, webserver, and
                        identified protections
  -pC, --payload-cache  View all payloads that have been cached inside of the
                        database
  -vC, --view-cache     View all the cache in the database, everything from
                        URLs to payloads
  --export FILE-TYPE    Export the already encoded payloads to a specified
                        file type and save them under the home(~/.whatwaf)
                        directory

misc arguments:
  arguments that don't fit in any other category

  --verbose             Run in verbose mode (more output)
  --update              Update WhatWaf to the newest development version
  --save FILENAME       Save the encoded payloads into a file
  --skip                Skip checking for bypasses and just identify the
                        firewall
  --verify-num INT      Change the request amount to verify if there really is
                        not a WAF present(*default=5)
  -W, --determine-webserver
                        Attempt to determine what web server is running on the
                        backend (IE Apache, Nginx, etc.. *default=False)
  --wafs                Output a list of possible firewalls that can be
                        detected by this program
  --tampers             Output a list of usable tamper script load paths

  --clean               Clean up WhatWaf home folders
```

## 下载和安装
### Installation
```
git clone https://github.com/Lunpopo/WhatWaf.git

cd WhatWaf 

pip install -r requirements.txt

python whatwaf.py -h
```

## 使用
### Usage

#### Demon Video: [![to_video](http://i67.tinypic.com/2daawow.png)](https://vimeo.com/247623511)

#### Proof of concept
First we'll run the website through WhatWaf and figure out which firewall protects it (if any):
![item1](http://i67.tinypic.com/142y9s6.png)

Next we'll go to that website and see what the page looks like:
![item2](http://i64.tinypic.com/262mjhl.png)

Hmm.. that doesn't really look like Cloudflare does it? Lets see what the headers say:
![item4](http://i66.tinypic.com/5txx5x.png)

And finally, lets try one of the bypasses that it tells us to try:
![item3](http://i66.tinypic.com/sdi3x0.png)

