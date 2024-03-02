from colorama import Fore
import os,sys,time,logging,requests,argparse,functools
from urllib.parse import urlparse
from requests.utils import default_user_agent
from pathlib import Path
import urllib.request
from requests.auth import HTTPBasicAuth
from random import choice
import concurrent.futures
from string import ascii_letters
from collections import defaultdict
from tqdm import tqdm

status_codes, methods_avail, paths = [200,204,301,302,307,401,403], ["GET", "POST", "HEAD", "PUT", "OPTIONS", "PATCH"], []
user_agent_list = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)', 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0)', 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; MDDCJS)', 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko', 'Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4', 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 'Mozilla/5.0 (Linux; Android 6.0.1; SAMSUNG SM-G570Y Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/4.0 Chrome/44.0.2403.133 Mobile Safari/537.36', 'Mozilla/5.0 (Linux; Android 5.0; SAMSUNG SM-N900 Build/LRX21V) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76 Mobile Safari/537.36', 'Mozilla/5.0 (Linux; Android 6.0.1; SAMSUNG SM-N910F Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/4.0 Chrome/44.0.2403.133 Mobile Safari/537.36', 'Mozilla/5.0 (Linux; U; Android-4.0.3; en-us; Galaxy Nexus Build/IML74K) AppleWebKit/535.7 (KHTML, like Gecko) CrMo/16.0.912.75 Mobile Safari/535.7', 'Mozilla/5.0 (Linux; Android 7.0; HTC 10 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.83 Mobile Safari/537.36', 'curl/7.35.0', 'Wget/1.15 (linux-gnu)', 'Lynx/2.8.8pre.4 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.12.23')

def pretty(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        func(*args, **kwargs)
        tqdm.write(Fore.GREEN + "(" + Fore.BLUE + '=' * 118 + Fore.GREEN + ")" + Fore.RESET)
    return wrapper

def lister(exts):
    if isinstance(exts, str):
        exts = [i for i in exts.split(',')]
    elif isinstance(exts, list):
        pass
    else:
        if exts == None:
            return ['']
        else:
            raise ValueError(f"{exts} type {type(exts)} is not valid! Need string or list.")
    if not type(exts[0])==int and not exts[0].isdigit() and '-' not in exts[0]:
        if exts != ['']:
            exts = ['.'+i if not i.startswith('.') else i for i in exts]
            exts.insert(0,'')
            try:
                exts.remove('.')
            except ValueError:
                pass
    else:
        try:
            for stat in exts[0:]:
                if type(stat)==str and '-' in stat:
                    exts.remove(stat)
                    stat = stat.strip()
                    start, end = map(int, stat.split('-'))
                    exts.extend(range(start, end + 1))
            exts = list(map(int, exts))
            exts.sort()
        except ValueError:
            raise ValueError(f"Status code in {exts} is not a valid integer.")
    return exts

class PathPlunderer(object):
    def __init__(self, url:str, wordfile:str, threads:int=15, exts:list=[''], logfile:str=None, codes:list=status_codes, user:str=None, password:str=None, force:bool=False, user_agent:str=default_user_agent(), proxy_url:str=None, insecure:str=False, timeout:int=10, redirect:bool=False, cookies:str=None, headers:str=None, methods:str="GET", data:str=None):
        file = Path(wordfile)
        if not file.exists():
            raise FileNotFoundError(f"{wordfile} doesn't exist")
        self.url = self.base_url = url if url.endswith('/') else url + '/'
        self.wordlist = ''
        self.wordfile = wordfile
        with open(wordfile) as f:
            self.wordlist = f.read().splitlines()
        self.threads = threads
        self.exts = lister(exts)
        self.logfile = logfile
        self.codes = lister(codes)
        self.user = user
        self.password = password
        self.force = force
        self.user_agent = user_agent or choice(user_agent_list)
        self.results = defaultdict(list)
        self.insecure = insecure
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.redirect= redirect
        self.cookies = cookies
        self.headers = headers
        self.methods = methods
        self.data = data
        self.auth = None

    def _brute(self, session:requests.Session, url:str, filename:str, pbar, data:str=None, methods:str="GET"):
        filename = filename.lstrip("/")
        if methods == "GET":
            resp = session.get(url + filename)
        elif methods == "POST":
            resp = session.post(url + filename, data=data)
        elif methods == "HEAD":
            resp = session.head(url + filename)
        elif methods == "PUT":
            resp = session.get(url + filename, data=data)
        elif methods == "OPTIONS":
            resp = session.get(url + filename)
        elif methods == "PATCH":
            resp = session.get(url + filename, data=data)
        if resp.url.endswith('/') and resp.status_code < 404 and resp.url != self.base_url and resp.url != url:
            paths.append(resp.url)
        pbar.update(1)
        if resp.status_code in self.codes and resp.url != url:
            if resp.status_code <= 299:
                result = " " + url + filename + Fore.GREEN + " (Status : " + str(resp.status_code) + ")" + Fore.RESET + " [Size : " + str(len(resp.content)) + "]" + Fore.GREEN + " ---> Found " + Fore.RESET
            elif resp.status_code <= 399:
                result = " " + url + filename + Fore.BLUE + " (Status : " + str(resp.status_code) + ") " + resp.url + Fore.RESET + " [Size : " + str(len(resp.content)) + "]" + Fore.BLUE + " ---> Moved " + Fore.RESET
            elif resp.status_code == 401:
                result = " " + url + filename + Fore.RED + " (Status : " + str(resp.status_code) + ")" + Fore.RESET + " [Size : " + str(len(resp.content)) + "]" + Fore.RED + "  ---> Unauthorized Access " + Fore.RESET
            elif resp.status_code == 403:
                result = " " + url + filename + Fore.RED + " (Status : " + str(resp.status_code) + ")" + Fore.RESET + " [Size : " + str(len(resp.content)) + "]" + Fore.RED + "  ---> Forbidden Access " + Fore.RESET
            elif resp.status_code == 404:
                result = " " + url + filename + Fore.RED + " (Status : " + str(resp.status_code) + ")" + Fore.RESET + " [Size : " + str(len(resp.content)) + "]" + Fore.RED + "  ---> Not Found " + Fore.RESET
            elif resp.status_code == 500:
                result = " " + url + filename + Fore.RED + " (Status : " + str(resp.status_code) + ")" + Fore.RESET + " [Size : " + str(len(resp.content)) + "]" + Fore.RED + "  ---> Server Error " + Fore.RESET
            else:
                result = " " + url + filename + Fore.CYAN + " (Status : " + str(resp.status_code) + ")" + Fore.RESET + " [Size : " + str(len(resp.content)) + "]" + Fore.RESET
            self.results[resp.status_code].append(resp.url)
            tqdm.write(result)
            if self.logfile:
                with open(self.logfile,'a') as f:
                    f.write(result+'\n')

    def checkAndRun(self):
        if not urlparse(self.url).scheme:
            try:
                http_response = requests.get("https://" + self.url)
                self.url = "https://" + self.url
            except:
                self.url = "http://" + self.url
        try:
            r = urllib.request.urlopen(self.url+''.join(choice(ascii_letters) for i in range(60)))
            tqdm.write(str(r.status))
        except urllib.error.HTTPError:
            r = None
        except urllib.error.URLError:
            tqdm.write(f"Do you have the proper address? Because {self.url} seems to be down.")
            sys.exit(1)
        if r and not self.force:
            tqdm.write("Website is wildcard matching. Do you really want to bruteforce this website?")
            sys.exit(0)
        if bool(self.user) and bool(self.password):
            r = requests.post(self.url,auth=HTTPBasicAuth(self.user,self.password))
            if r.status_code != 200:
                tqdm.write("Don't have proper credentials. Please recheck.")
                sys.exit(0)
            self.auth = HTTPBasicAuth(self.user, self.password)
        if self.logfile:
            with open(self.logfile,'w'):
                pass
        if self.methods not in methods_avail:
            print("Enter a valid HTTP method to continue..Exiting")
            sys.exit(0)
        self._header()
        self.start = time.perf_counter()
        self.base_url = self.url
        self.Run()
        if self.redirect:
            for u in paths:
                    self.url = u
                    print("\n " + Fore.BLUE + "[" + Fore.RESET + "+" + Fore.BLUE + "]" + Fore.RESET + " Entering Path: " + u + "\n")
                    self.Run()
        self._print_func()
        self._print_func(f" Time elapsed : {time.perf_counter() - self.start}")
        return self.results

    def Run(self):
        session = requests.Session()
        if self.insecure:                   # --insecure
            session.verify = False
        session.timeout = self.timeout      # --timeout
        if self.proxy_url != '':
            session.verify = False
            session.proxies = {             # --proxy
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            logging.captureWarnings(True)
        session.headers['User-Agent'] = self.user_agent
        if self.headers:
            self.headers = [i.strip() for i in self.headers.split(',')]     # --headers
            for i in self.headers:
                h1,h2 = i.split(':',1)
                session.headers[h1.strip()] = h2.strip()
        if self.cookies:
            self.cookies = [i for i in self.cookies.split(',')]     # --cookies
            for i in self.cookies:
                c1,c2 = i.split('=',1)
                session.cookies.set(c1.strip(),c2.strip())
        if bool(self.user) and bool(self.password):
            session.auth = self.auth
        list_length = len(self.wordlist) * len(self.exts) #if not self.completed else len(self.wordlist) * len(self.exts) * len(paths)
        wordlist =  (i.rstrip("/").strip() if e=='' else i.rstrip("/").strip()+e for i in self.wordlist for e in self.exts) #wordlist =  (i.rstrip("/")+'/'' if e=='' else i.rstrip("/")+e for i in self.wordlist for e in self.exts)
        clientpool, urllist = (session for i in range(list_length)), (self.url for i in range(list_length))
        pbar = tqdm(total=list_length, leave=False)
        pbars = (pbar for i in range(list_length))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._brute, client, url, word, pbar,self.data,self.methods) for client, url, word in zip(clientpool, urllist, wordlist)]
            try:
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
                executor.shutdown(wait=False)
                print("\n Keyboard Interupt detected. Cancelling the current task..." if self.redirect else "\n Keyboard Interupt detected. Exiting bye bye...")

    def _header(self):
        self._print_func()
        self._print_func(__version__)
        header_text = " Url:".ljust(20) + self.url +'\n'
        header_text += " Threads:".ljust(20) + str(self.threads) + '\n'
        header_text += " Wordlist:".ljust(20) + self.wordfile + '\n'
        header_text += " Status Codes:".ljust(20) + ','.join(map(str,self.codes)) + '\n'
        header_text += " User Agent:".ljust(20) + self.user_agent + '\n'
        header_text += " Timeout:".ljust(20) + str(self.timeout) + '\n'
        header_text += " Method:".ljust(20) + self.methods + '\n'
        header_text += " Extensions:".ljust(20) + ','.join((i.lstrip('.') for i in self.exts if i != ''))
        self._print_func(header_text)
    
    @pretty
    def _print_func(self, text:str=''):
        end = '\n'
        if text == '':
            end = ''
        tqdm.write(text,end=end)

if __name__ == "__main__":
    __version__ = Fore.YELLOW + """
     ____          _    _      ____   _                    _
    |  _ \\   __ _ | |_ | |__  |  _ \\ | | _   _  _ __    __| |  ___  _ __   ___  _ __
    | |_) | / _` || __|| '_ \\ | |_) || || | | || '_ \\  / _` | / _ \\| '__| / _ \\| '__|
    |  __/ | (_| || |_ | | | ||  __/ | || |_| || | | || (_| ||  __/| |   |  __/| |    
    |_|     \\__,_| \\__||_| |_||_|    |_| \\__,_||_| |_| \\__,_| \\___||_|    \\___||_| """+Fore.RESET + "v1.0" + "\n\n\t\t\t\t\t\t\t\t" + " by" + Fore.RED + " VICTOR AZARIAH "+ Fore.RESET +"\n" 
    prog = __version__.split()[0].lower()
    parser = argparse.ArgumentParser(prog=prog, description="Python Web Directory and File Brute Forcer")
    parser = argparse.ArgumentParser(description="Python Web Directory and File Brute Forcer")
    parser.add_argument('-u', "--url",required=True, help="The url to start brute foroce from.")
    parser.add_argument('-w', "--wordlist", dest="wordfile", required=True, help="The wordlist to use for brute force.")
    parser.add_argument('--user', help="Username for Basic Auth")
    parser.add_argument('--pass', dest="password", help="Password for Basic Auth")
    parser.add_argument('-x', dest="exts", type=lister, default=[''], help="File Extensions - must be comma delimited list (Example: -x php,pdf)")
    parser.add_argument('-t', "--threads", type=int, default=15, help="The amount of threads to use.")
    parser.add_argument('-o', "--output", dest="logfile", help="File to log results. (Example: -o Results.txt)")
    parser.add_argument('-s', dest="codes", type=lister, default=[200,204,301,302,307,401,403], help="HTTP Status Codes to accept in a comma delimited list. Default - 200,204,301,302,307,401,403")
    parser.add_argument('-m', dest="methods", default="GET", help='Use the following HTTP methods POST, HEAD, PUT, OPTIONS, PATCH. (default "GET")')
    parser.add_argument('-f', dest="force", action="store_true", default=False, help="Force wildcard proccessing.")
    agent_help = "Custom or random user agent. -z 'User-agent' for custom. -z for random"
    parser.add_argument('-z', "--user-agent", dest="user_agent", default=default_user_agent(), nargs='?', help=agent_help)
    parser.add_argument('-p', "--proxy", dest="proxy_url", default='', help="Proxy to use for requests [http(s)://host:port]")
    parser.add_argument('-r', "--follow-redirect", dest="redirect", default=False, action="store_true", help="Follow redirects")
    parser.add_argument('-k', "--insecure", dest="insecure", action="store_true", default=False, help="Allow insecure server connections")
    parser.add_argument("--timeout", dest="timeout", default=10, help="HTTP Timeout (default 10s)")
    parser.add_argument('-c', "--cookies", dest="cookies", default='', help="Cookies to use for the requests (Example: -c 'session=123456')")
    parser.add_argument('-H', "--headers", dest="headers", default='', help="Specify HTTP headers to use for the requests (Example: -H 'Header1:val1','Header2:val2'")
    parser.add_argument('-d', "--data", dest="data", default="", help='Enter the data to be inside the body of POST, PUT, PATCH methods (Example: -d "rawdata")')

    try:
        args = parser.parse_args()
        scanner = PathPlunderer(**vars(args))
        scanner.checkAndRun()
    except KeyboardInterrupt:
        print("\nKeyboard Interupt detected. Cancelling remaining tasks...")
        sys.exit(1)
'''
python PathPlunderer.py -u http://testphp.vulnweb.com -w wordlist.txt -k -x php
Todo:


New Features:
1) Accepts Insecure Communication using option -k (or) --insecure
2) Even someone give only domain name in url, it will automatically find the correct protocol for it
3) Accepting status codes in range (200-400) and sort them
4) Using Fores
5) Inserted an ASCII Art in version
6) Storing status 403 and 200 url's
7) While being recursive stop the current path by using ctrl+c
8) --timeout duration                HTTP Timeout (default 10s)
9) -p, --proxy                            Proxy to use for requests [http(s)://host:port]
10) -r, --follow-redirect                 Follow redirects
11) Showing the response size
12) -c, --cookies string                  Cookies to use for the requests (Example: -c 'session=123456')
13) -H, --headers string                  Specify HTTP headers, -H 'Header1:val1,Header2:val2'
14) -m, --method string                   Use the following HTTP method (default "GET")
15) -d, --data  Storing                   Enter the data to be inside the body of POST, PUT, PATCH methods
16) Using Basic Auth
'''
