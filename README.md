# 🦈 TShark 命令生成器

一个可视化的 TShark 命令生成工具，专为电子取证和 CTF 流量分析设计。

![Preview](https://img.shields.io/badge/TShark-GUI-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

## ✨ 功能特性

- **点击式命令组合** - 无需记忆复杂参数，通过界面点选即可生成命令
- **12个快捷场景** - 一键生成常用取证分析命令
- **完整参数覆盖** - 支持过滤器、输出格式、统计分析等核心功能
- **暗色/亮色主题** - 自动保存用户偏好
- **一键复制** - 快速将命令复制到剪贴板

## 🎯 快捷场景

| 场景 | 用途 |
|------|------|
| 📊 协议分布 | 分析流量中的协议层级分布 |
| 🔗 IP通信对 | 查看IP之间的会话关系 |
| 🌐 HTTP请求 | 提取所有HTTP请求信息 |
| 🔍 DNS查询 | 提取DNS查询记录 |
| 🔑 提取凭据 | 查找FTP/HTTP明文凭据 |
| 🖥️ User-Agent | 分析客户端特征 |
| 🍪 Cookies | 提取Cookie信息 |
| 📤 POST数据 | 分析POST请求数据 |
| 🔄 TCP流追踪 | 还原TCP会话内容 |
| ⚠️ 可疑流量 | 检测SYN扫描等异常 |
| 📈 时间线 | 按时间顺序分析流量 |
| 🔬 专家分析 | 获取专家级诊断信息 |

## 🚀 使用方法

1. 直接打开 `index.html` 文件
2. 选择/输入 pcap 文件路径
3. 点击快捷场景或手动配置选项
4. 复制生成的命令到终端执行

## 📂 项目结构

```
tshark-gui/
├── index.html   # 主页面
├── style.css    # 样式文件（支持暗色/亮色主题）
├── app.js       # 核心逻辑
└── README.md    # 说明文档
```

## 🛠️ 技术栈

- 纯 HTML/CSS/JavaScript
- 无需安装任何依赖
- 兼容主流现代浏览器

## 📝 License

MIT License
