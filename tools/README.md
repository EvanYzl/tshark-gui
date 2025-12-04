# 加密Webshell流量解密工具

本目录包含用于解密加密型Webshell流量的开源工具。

## 工具列表

### 1. WSTDecryptor (哥斯拉解密)

**支持类型**: Godzilla、Weevely3、SharPyShell

**安装**:
```bash
cd WSTDecryptor
pip install -r requirements.txt
```

**使用**:
```bash
# 自动查找webshell
python WSTDecryptor.py findshell -p sample.pcapng

# 解密Godzilla流量
python WSTDecryptor.py godzilla -p sample.pcapng -i <server_ip> -k <key>
```

---

### 2. behinder-decryptor (冰蝎解密)

**支持类型**: 冰蝎 PHP/ASP/ASPX/JSP

**安装**:
```bash
cd behinder-decryptor
pip install -r requirements.txt
```

**使用**:
```bash
python Behinder-Decrypt.py -f capture.pcap -u /uploads/shell.php -t php -k e45e329feb5d925b -p
```

**参数说明**:
- `-f`: pcap文件路径
- `-u`: Webshell的URL路径
- `-t`: 脚本类型 (php/asp/aspx/jsp)
- `-k`: Webshell密钥 (16位)
- `-p`: 启动Web预览界面

---

## 常见密钥

| Webshell | 默认密钥 |
|----------|----------|
| 冰蝎3.0 | `e45e329feb5d925b` (rebeyond的MD5前16位) |
| 哥斯拉 | `3c6e0b8a9c15224a` (pass的MD5前16位) |

## 相关资源

- [WSTDecryptor GitHub](https://github.com/rb3nzr/WSTDecryptor)
- [behinder-decryptor GitHub](https://github.com/ba0gu0/behinder-decryptor)
