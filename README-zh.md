以下是优化后的 README.md，主要改进点：结构更清晰、重点更突出、代码示例更规范、补充了必要细节：

# SSLMask

![License](https://img.shields.io/badge/license-MIT-blue.svg)  
![GitHub stars](https://img.shields.io/github/stars/LanXuage/sslmask?style=social)  
[English Documentation](https://github.com/LanXuage/sslmask/blob/main/README.md) | [中文文档](https://github.com/LanXuage/sslmask/blob/main/README-zh.md)

## 🔍 项目简介

**SSLMask** 是一款轻量级 TLS 指纹伪装工具，通过以下核心功能帮助用户绕过服务器指纹检测：

1. **Socks5 代理服务**：启动带 TLS 指纹伪装的代理，支持多用户认证
2. **TLS 测试客户端**：使用伪装指纹发起定向 TLS 连接测试

## 🚀 核心功能

| 功能模块       | 特性描述                                                                |
| -------------- | ----------------------------------------------------------------------- |
| **代理服务器** | ✅ 支持多用户认证<br>✅ 自动生成/自定义 TLS 证书<br>✅ 实时指纹伪装配置 |
| **测试客户端** | ✅ 多目标并发测试<br>✅ 详细连接状态报告<br>✅ 支持调试模式             |
| **指纹支持**   | 🟢 Microsoft Edge 133（默认）<br>🔜 后续将支持 Chrome/Firefox/Safari 等 |

## 📦 安装指南

```bash
pip install sslmask
```

## 🛠 使用说明

### 1. 启动代理服务器

```bash
sslmask server [OPTIONS]

# 基础用法
sslmask server 0.0.0.0:1080 --fingerprint MSEdge133

# 完整参数说明
Options:
  -h, --host TEXT      监听地址 (default: 0.0.0.0)
  -p, --port INTEGER   监听端口 (default: 1080)
  -fp, --fingerprint TEXT
                       伪装指纹 (default: MSEdge133)
  -k, --key TEXT       TLS 私钥文件 (自动生成时可不填)
  -c, --cert TEXT      TLS 证书文件 (自动生成时可不填)
  -up, --userpass TEXT
                       认证用户 (格式: user:pass, 可重复添加)
  -d, --debug          开启调试模式
```

### 2. 发起 TLS 测试

```bash
sslmask client [OPTIONS] target:port

# 基础用法
sslmask client example.com:443 --fingerprint MSEdge133

# 完整参数说明
Options:
  -fp, --fingerprint TEXT
                       伪装指纹 (default: MSEdge133)
  -d, --debug          开启调试模式
```

## 📝 示例演示

### 场景 1：基础代理服务

```bash
# 启动默认配置的代理服务器
sslmask server
```

### 场景 2：带认证的代理服务

```bash
# 启动需要用户名密码的代理
sslmask server --userpass admin:123456
```

### 场景 3：自定义证书配置

```bash
# 使用自定义证书启动代理
sslmask server --key server.key --cert server.crt
```

### 场景 4：发起 TLS 测试

```bash
# 测试目标网站的 TLS 指纹伪装效果
sslmask client --debug example.com:443
```

## 🛡 安全说明

1. 自动生成的证书仅用于测试，生产环境请使用 CA 签发证书
2. 建议定期更换代理认证密码
3. 指纹伪装效果可能因服务端检测策略升级而变化

## 🤝 贡献指南

1. Fork 项目并创建开发分支
2. 提交代码前运行测试：`pytest tests/`
3. 提交 Pull Request 时需包含：
   - 功能描述
   - 测试用例
   - 兼容性说明

## 📜 许可证

本项目采用 [MIT 许可证](LICENSE)，允许商业使用、修改和分发。

## 🔗 联系方式

GitHub Issues: [https://github.com/LanXuage/sslmask/issues](https://github.com/LanXuage/sslmask/issues)  
邮箱：lanxuage@gmail.com（建议优先使用 GitHub Issues）
