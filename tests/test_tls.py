import socket

from sslmask.tls import TLS


if __name__ == "__main__":
    tls = TLS(host="autotest.dnslog.fun")
    tls.connect()
    tls.send(b"GET /\r\n\r\n")
    print("res:", tls.readuntil("\r\n\r\n"))
    tls.close()
