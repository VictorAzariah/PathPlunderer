# PathPlunderer

A fast, simple, recursive content discovery tool written in Python. This tool is used to brute-force URIs (directories and files) in websites.

# Changes

## 2.0

- Accepts insecure communication using option `-k` (or) `--insecure`
- Even if someone gives only the domain name in the URL field, it will automatically find the correct protocol for it
- Accept status codes in the range (200-400) and sort them
- While being recursive, stop the current path by using ctrl+c
- `--timeout duration`                    HTTP TIMEOUT (default 10s)
- `-p`, `--proxy`                           Proxy to use for requests [http(s)://host:port]
- `-r`, `--follow-redirect`                 Follow redirects
- Showing the response size
- `-c`, `--cookies string`                  Cookies to use for the requests
- `-H`, `--headers string`                  Specify HTTP headers
- `-m`, `--method string`                   Use the following HTTP method (default "GET")
- `-d`, `--data`                            Enter the data to be inside the body of POST, PUT, PATCH methods
- Find directories and files using Basic Auth

# License

This project is licensed under the [Apache-2.0 license](LICENSE).

# Manual

## Installation

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

Help is built-in!

- `python PathPlunderer.py -h (or) --help` - outputs the help menu.

```text
usage: PathPlunderer.py [-h] -u URL -w WORDFILE [--user USER] [--pass PASSWORD] [-x EXTS] [-t THREADS] [-o LOGFILE]
                        [-s CODES] [-m METHODS] [-f] [-z [USER_AGENT]] [-p PROXY_URL] [-r] [-k] [--timeout TIMEOUT]
                        [-c COOKIES] [-H HEADERS] [-d DATA]

Python Web Directory and File Brute Forcer

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     The URL to start brute force from.
  -w WORDFILE, --wordlist WORDFILE
                        The wordlist to use for brute force.
  --user USER           Username for Basic Auth
  --pass PASSWORD       Password for Basic Auth
  -x EXTS               File Extensions - must be comma delimited list (Example: -x php, pdf)
  -t THREADS, --threads THREADS
                        The number of threads to use.
  -o LOGFILE, --output LOGFILE
                        File to log results. (Example: -o Results.txt)
  -s CODES              HTTP Status Codes to accept in a comma delimited list. Default - 200,204,301,302,307,401,403
  -m METHODS            Use the following HTTP methods: POST, HEAD, PUT, OPTIONS, PATCH. (default "GET")
  -f                    Force wildcard processing.
  -z [USER_AGENT], --user-agent [USER_AGENT]
                        Custom or random user agent. -z 'User-agent' for custom. -z for random
  -p PROXY_URL, --proxy PROXY_URL
                        Proxy to use for requests [http(s)://host:port]
  -r, --follow-redirect
                        Follow redirects
  -k, --insecure        Allow insecure server connections
  --timeout TIMEOUT     HTTP TIMEOUT (default 10s)
  -c COOKIES, --cookies COOKIES
                        Cookies to use for the requests (Example: -c 'session=123456')
  -H HEADERS, --headers HEADERS
                        Specify HTTP headers to use for the requests (Example: -H 'Header1:val1', 'Header2:val2'
  -d DATA, --data DATA  Enter the data to be inside the body of POST, PUT, PATCH methods (Example: -d "rawdata"
```

## Examples

```text
python PathPlunderer.py -u <url> -w <wordlist> -t <threads>
```

A normal sample run goes like this:

![poc.gif](poc.gif "poc.gif")

# Credits

*Wordlist Credits: [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)<br>You can find awesome wordlists from there!*

P.S.: There are various sizes of wordlists inside /Wordlists, do check it out too!

Have fun!✌
