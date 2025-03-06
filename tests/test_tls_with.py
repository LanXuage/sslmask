from sslmask.tls import TLS


if __name__ == "__main__":
    with TLS("autotest.dnslog.fun") as tls:
        print("with")
