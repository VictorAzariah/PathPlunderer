# PathPlunderer

PathPlunderer is a tool used to brute-force URIs (directories and files) in websites.

# Changes

## 2.0

- Accepts insecure communication using option -k (or) --insecure
- Even if someone gives only the domain name in the URL field, it will automatically find the correct protocol for it
- Accepting status codes in range (200-400) and sort them
- While being recursive stop the current path by using ctrl+c
- --timeout duration                    HTTP Timeout (default 10s)
- -p, --proxy                           Proxy to use for requests [http(s)://host:port]
- -r, --follow-redirect                 Follow redirects
- Showing the response size
- -c, --cookies string                  Cookies to use for the requests (Example: -c 'session=123456')
- -H, --headers string                  Specify HTTP headers, -H 'Header1:val1,Header2:val2'
- -m, --method string                   Use the following HTTP method (default "GET")
- -d, --data  Storing                   Enter the data to be inside the body of POST, PUT, PATCH methods
- Find directories and files using Basic Auth

# License

See the LICENSE file.

# Manual

## Easy Installation

This command will clone the GitHub repository into the folder `PathPlunderer`:

```bash
git clone https://github.com/VictorAzariah/PathPlunderer
```

Use this command to enter the `PathPlunderer` folder:

```bash
cd PathPlunderer
```

This command will install the required python packages to run `PathPlunderer` tool:

```bash
pip install -r requirements.txt
```

## Options

```text
usage: PathPlunderer.py [-h] -u URL -w WORDFILE [--user USER] [--pass PASSWORD] [-x EXTS] [-t THREADS] [-o LOGFILE]
                        [-s CODES] [-m METHODS] [-f] [-z [USER_AGENT]] [-p PROXY_URL] [-r] [-k] [--timeout TIMEOUT]
                        [-c COOKIES] [-H HEADERS] [-d DATA]

Python Web Directory and File Brute Forcer

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     The url to start brute foroce from.
  -w WORDFILE, --wordlist WORDFILE
                        The wordlist to use for brute force.
  --user USER           Username for Basic Auth
  --pass PASSWORD       Password for Basic Auth
  -x EXTS               File Extensions - must be comma delimited list (Example: -x php,pdf)
  -t THREADS, --threads THREADS
                        The amount of threads to use.
  -o LOGFILE, --output LOGFILE
                        File to log results. (Example: -o Results.txt)
  -s CODES              HTTP Status Codes to accept in a comma delimited list. Default - 200,204,301,302,307,401,403
  -m METHODS            Use the following HTTP methods POST, HEAD, PUT, OPTIONS, PATCH. (default "GET")
  -f                    Force wildcard proccessing.
  -z [USER_AGENT], --user-agent [USER_AGENT]
                        Custom or random user agent. -z 'User-agent' for custom. -z for random
  -p PROXY_URL, --proxy PROXY_URL
                        Proxy to use for requests [http(s)://host:port]
  -r, --follow-redirect
                        Follow redirects
  -k, --insecure        Allow insecure server connections
  --timeout TIMEOUT     HTTP Timeout (default 10s)
  -c COOKIES, --cookies COOKIES
                        Cookies to use for the requests (Example: -c 'session=123456')
  -H HEADERS, --headers HEADERS
                        Specify HTTP headers to use for the requests (Example: -H 'Header1:val1','Header2:val2'
  -d DATA, --data DATA  Enter the data to be inside the body of POST, PUT, PATCH methods (Example: -d "rawdata"

D:\Python Scripts\PathPlunderer>python PathPlunderer.py -h
usage: PathPlunderer.py [-h] -u URL -w WORDFILE [--user USER] [--pass PASSWORD] [-x EXTS] [-t THREADS] [-o LOGFILE]
                        [-s CODES] [-m METHODS] [-f] [-z [USER_AGENT]] [-p PROXY_URL] [-r] [-k] [--timeout TIMEOUT]
                        [-c COOKIES] [-H HEADERS] [-d DATA]

Python Web Directory and File Brute Forcer

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     The url to start brute foroce from.
  -w WORDFILE, --wordlist WORDFILE
                        The wordlist to use for brute force.
  --user USER           Username for Basic Auth
  --pass PASSWORD       Password for Basic Auth
  -x EXTS               File Extensions - must be comma delimited list (Example: -x php,pdf)
  -t THREADS, --threads THREADS
                        The amount of threads to use.
  -o LOGFILE, --output LOGFILE
                        File to log results. (Example: -o Results.txt)
  -s CODES              HTTP Status Codes to accept in a comma delimited list. Default - 200,204,301,302,307,401,403
  -m METHODS            Use the following HTTP methods POST, HEAD, PUT, OPTIONS, PATCH. (default "GET")
  -f                    Force wildcard proccessing.
  -z [USER_AGENT], --user-agent [USER_AGENT]
                        Custom or random user agent. -z 'User-agent' for custom. -z for random
  -p PROXY_URL, --proxy PROXY_URL
                        Proxy to use for requests [http(s)://host:port]
  -r, --follow-redirect
                        Follow redirects
  -k, --insecure        Allow insecure server connections
  --timeout TIMEOUT     HTTP Timeout (default 10s)
  -c COOKIES, --cookies COOKIES
                        Cookies to use for the requests (Example: -c 'session=123456')
  -H HEADERS, --headers HEADERS
                        Specify HTTP headers to use for the requests (Example: -H 'Header1:val1','Header2:val2'
  -d DATA, --data DATA  Enter the data to be inside the body of POST, PUT, PATCH methods (Example: -d "rawdata")
```

## Examples


```text
python PathPlunderer.py -u <url> -w <wordlist>
```

Normal sample run goes like this:

```text
python PathPlunderer.py -u http://testphp.vulnweb.com -w wordlist.txt -k -x php
(======================================================================================================================)

     ____          _    _      ____   _                    _
    |  _ \   __ _ | |_ | |__  |  _ \ | | _   _  _ __    __| |  ___  _ __   ___  _ __
    | |_) | / _` || __|| '_ \ | |_) || || | | || '_ \  / _` | / _ \| '__| / _ \| '__|
    |  __/ | (_| || |_ | | | ||  __/ | || |_| || | | || (_| ||  __/| |   |  __/| |
    |_|     \__,_| \__||_| |_||_|    |_| \__,_||_| |_| \__,_| \___||_|    \___||_| v1.0

                                                                 by VICTOR AZARIAH

(======================================================================================================================)
 Url:               http://testphp.vulnweb.com/
 Threads:           15
 Wordlist:          wordlist.txt
 Status Codes:      200,204,301,302,307,401,403
 User Agent:        python-requests/2.31.0
 Timeout:           10
 Method:            GET
 Extensions:        php
(======================================================================================================================)
 http://testphp.vulnweb.com/login.php (Status : 200) (Size : 5523) ---> Found
 http://testphp.vulnweb.com/redir.php (Status : 302) http://testphp.vulnweb.com/redir.php (Size : 0) ---> Moved
 http://testphp.vulnweb.com/pictures (Status : 200) (Size : 2669) ---> Found
 http://testphp.vulnweb.com/disclaimer.php (Status : 200) (Size : 5524) ---> Found
 http://testphp.vulnweb.com/favicon.ico (Status : 200) (Size : 894) ---> Found
 http://testphp.vulnweb.com/CVS (Status : 200) (Size : 595) ---> Found
 http://testphp.vulnweb.com/images (Status : 200) (Size : 377) ---> Found
 http://testphp.vulnweb.com/admin (Status : 200) (Size : 262) ---> Found
 http://testphp.vulnweb.com/crossdomain.xml (Status : 200) (Size : 224) ---> Found
 http://testphp.vulnweb.com/vendor (Status : 200) (Size : 268) ---> Found
 http://testphp.vulnweb.com/secured (Status : 200) (Size : 0) ---> Found
 http://testphp.vulnweb.com/cgi-bin (Status : 403) (Size : 276)  ---> Forbidden Access
 http://testphp.vulnweb.com/product.php (Status : 200) (Size : 5056) ---> Found
 http://testphp.vulnweb.com/search.php (Status : 200) (Size : 4732) ---> Found
 http://testphp.vulnweb.com/404.php (Status : 200) (Size : 5270) ---> Found
 http://testphp.vulnweb.com/signup.php (Status : 200) (Size : 6033) ---> Found
 http://testphp.vulnweb.com/search.php (Status : 200) (Size : 4732) ---> Found
 http://testphp.vulnweb.com/login.php (Status : 200) (Size : 5523) ---> Found
 http://testphp.vulnweb.com/userinfo.php (Status : 200) (Size : 5523) ---> Found
 http://testphp.vulnweb.com/cart.php (Status : 200) (Size : 4903) ---> Found
 http://testphp.vulnweb.com/categories.php (Status : 200) (Size : 6115) ---> Found
 http://testphp.vulnweb.com/logout.php (Status : 200) (Size : 4830) ---> Found
 http://testphp.vulnweb.com/index.php (Status : 200) (Size : 4958) ---> Found
 http://testphp.vulnweb.com/comment.php (Status : 200) (Size : 4958) ---> Found
 http://testphp.vulnweb.com/guestbook.php (Status : 200) (Size : 5390) ---> Found
 http://testphp.vulnweb.com/AJAX (Status : 200) (Size : 4236) ---> Found
(======================================================================================================================)
 Time elapsed : 2.684562799986452
(======================================================================================================================)
```
