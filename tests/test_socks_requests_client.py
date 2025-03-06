import requests

proxies = {
    "http": "socks5://192.168.31.45:61080",
    "https": "socks5://192.168.31.45:61080",
}

resp = requests.get(
    "http://autotest.dnslog.fun", allow_redirects=False, proxies=proxies
)
print(resp.text)
