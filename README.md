# SSLMask

![License](https://img.shields.io/badge/license-MIT-blue.svg)  
![GitHub stars](https://img.shields.io/github/stars/LanXuage/sslmask?style=social)  
[English Documentation](https://github.com/LanXuage/sslmask/blob/main/README.md) | [中文文档](https://github.com/LanXuage/sslmask/blob/main/README-zh.md)

## 🔍 Project Overview

**SSLMask** is a lightweight TLS fingerprint spoofing tool that helps users bypass server fingerprint detection through two core features:

1. **Socks5 Proxy Service**: Start a proxy with TLS fingerprint spoofing, supporting multi-user authentication
2. **TLS Test Client**: Initiate targeted TLS connection tests using spoofed fingerprints

## 🚀 Core Features

| Feature Module          | Key Capabilities                                                                                                            |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Proxy Server**        | ✅ Multi-user authentication support<br>✅ Auto-generated/custom TLS certificates<br>✅ Real-time fingerprint configuration |
| **Test Client**         | ✅ Multi-target concurrent testing<br>✅ Detailed connection status reporting<br>✅ Debug mode support                      |
| **Fingerprint Support** | 🟢 Microsoft Edge 133 (default)<br>🔜 Coming soon: Chrome/Firefox/Safari                                                    |

## 📦 Installation

```bash
pip install sslmask
```

## 🛠 Usage Guide

### 1. Start Proxy Server

```bash
sslmask server [OPTIONS]

# Basic usage
sslmask server 0.0.0.0:1080 --fingerprint MSEdge133

# Full options
Options:
  -h, --host TEXT      Listening address (default: 0.0.0.0)
  -p, --port INTEGER   Listening port (default: 1080)
  -fp, --fingerprint TEXT
                       Spoofed fingerprint (default: MSEdge133)
  -k, --key TEXT       TLS private key file (optional for auto-generation)
  -c, --cert TEXT      TLS certificate file (optional for auto-generation)
  -up, --userpass TEXT
                       Authentication user (format: user:pass, can add multiple)
  -d, --debug          Enable debug mode
```

### 2. Initiate TLS Test

```bash
sslmask client [OPTIONS] target:port

# Basic usage
sslmask client example.com:443 --fingerprint MSEdge133

# Full options
Options:
  -fp, --fingerprint TEXT
                       Spoofed fingerprint (default: MSEdge133)
  -d, --debug          Enable debug mode
```

## 📝 Example Scenarios

### Scenario 1: Basic Proxy Service

```bash
# Start proxy with default configuration
sslmask server
```

### Scenario 2: Authenticated Proxy

```bash
# Start proxy requiring username/password
sslmask server --userpass admin:123456
```

### Scenario 3: Custom Certificate

```bash
# Start proxy with custom certificate
sslmask server --key server.key --cert server.crt
```

### Scenario 4: TLS Connection Test

```bash
# Test TLS fingerprint spoofing against a target site
sslmask client --debug example.com:443
```

## 🛡 Security Notes

1. Auto-generated certificates are for testing only - use CA-issued certificates in production
2. Regularly rotate proxy authentication passwords
3. Fingerprint spoofing effectiveness may vary with server detection strategy updates

## 🤝 Contribution Guidelines

1. Fork the repository and create a development branch
2. Run tests before submission: `pytest tests/`
3. Include in Pull Requests:
   - Feature description
   - Test cases
   - Compatibility notes

## 📜 License

This project is licensed under the [MIT License](LICENSE), allowing commercial use, modification, and distribution.

## 🔗 Contact

GitHub Issues: [https://github.com/LanXuage/sslmask/issues](https://github.com/LanXuage/sslmask/issues)  
Email: your-email@example.com (GitHub Issues preferred)
