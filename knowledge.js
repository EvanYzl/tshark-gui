/**
 * CTF 流量分析知识库
 * 包含所有CTF和电子取证流量分析题型分类与解题指南
 */
const knowledgeBase = {
    // 知识库分类
    categories: [
        {
            id: 'protocol',
            name: '协议分析',
            icon: '🔬',
            description: '各类网络协议的流量特征和分析方法'
        },
        {
            id: 'extraction',
            name: '数据提取',
            icon: '📦',
            description: '从流量中提取文件、凭证和隐藏数据'
        },
        {
            id: 'attack',
            name: '攻击识别',
            icon: '🎯',
            description: '识别各类网络攻击和恶意行为'
        },
        {
            id: 'stego',
            name: '隐写术',
            icon: '🔏',
            description: '流量中的隐写和隐蔽通信检测'
        },
        {
            id: 'crypto',
            name: '加密解密',
            icon: '🔐',
            description: 'TLS/SSL解密和加密流量分析'
        },
        {
            id: 'wireless',
            name: '无线安全',
            icon: '📡',
            description: 'WiFi、蓝牙和无线协议分析'
        },
        {
            id: 'forensics',
            name: '取证分析',
            icon: '🔍',
            description: '综合取证和攻击溯源技术'
        },
        {
            id: 'special',
            name: '特殊协议',
            icon: '⚙️',
            description: 'USB、工控等特殊协议分析'
        }
    ],

    // 知识条目
    entries: [
        // ========== 协议分析 ==========
        {
            id: 'http-analysis',
            category: 'protocol',
            title: 'HTTP协议分析',
            difficulty: 'easy',
            tags: ['HTTP', 'Web', '基础'],
            description: 'HTTP请求响应分析，Cookie、表单数据提取',
            tsharkFilter: 'http',
            tsharkFields: ['frame.number', 'ip.src', 'ip.dst', 'http.request.method', 'http.request.uri', 'http.response.code'],
            tips: [
                '使用 `http.request.method == "POST"` 过滤登录请求',
                '查找 `http.cookie` 提取会话信息',
                '导出HTTP对象: File > Export Objects > HTTP'
            ],
            commands: [
                'tshark -r file.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri',
                'tshark -r file.pcap -Y "http.request.method == POST" -T fields -e http.file_data'
            ],
            references: ['Wireshark HTTP过滤器', 'Follow HTTP Stream']
        },
        {
            id: 'dns-analysis',
            category: 'protocol',
            title: 'DNS协议分析',
            difficulty: 'easy',
            tags: ['DNS', '域名', '基础'],
            description: 'DNS查询响应分析，可疑域名检测',
            tsharkFilter: 'dns',
            tsharkFields: ['frame.number', 'ip.src', 'dns.qry.name', 'dns.resp.type', 'dns.a'],
            tips: [
                '使用 `dns.qry.name contains "flag"` 搜索特定域名',
                '检查异常长的域名(可能是DNS隧道)',
                '关注TXT记录可能隐藏数据'
            ],
            commands: [
                'tshark -r file.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name | sort | uniq -c',
                'tshark -r file.pcap -Y "dns.txt" -T fields -e dns.txt'
            ],
            references: ['DNS记录类型', 'DNS隧道检测']
        },
        {
            id: 'ftp-analysis',
            category: 'protocol',
            title: 'FTP协议分析',
            difficulty: 'easy',
            tags: ['FTP', '文件传输', '凭证'],
            description: 'FTP登录凭证和文件传输分析',
            tsharkFilter: 'ftp || ftp-data',
            tsharkFields: ['ip.src', 'ip.dst', 'ftp.request.command', 'ftp.request.arg', 'ftp.response.code'],
            tips: [
                'FTP是明文协议，用户名密码可直接获取',
                '使用 `ftp.request.command == "PASS"` 提取密码',
                'FTP-DATA端口传输文件内容'
            ],
            commands: [
                'tshark -r file.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.arg',
                'tshark -r file.pcap -Y "ftp.request.command == RETR" -T fields -e ftp.request.arg'
            ],
            references: ['FTP命令列表', 'Follow TCP Stream']
        },
        {
            id: 'smtp-analysis',
            category: 'protocol',
            title: 'SMTP/邮件分析',
            difficulty: 'medium',
            tags: ['SMTP', 'Email', 'MIME'],
            description: '邮件协议分析，邮件内容和附件提取',
            tsharkFilter: 'smtp || imf',
            tsharkFields: ['ip.src', 'smtp.req.parameter', 'imf.from', 'imf.to', 'imf.subject'],
            tips: [
                'SMTP AUTH凭证通常是Base64编码',
                '使用IMF过滤器解析邮件头部',
                '附件可能Base64编码在邮件体中'
            ],
            commands: [
                'tshark -r file.pcap -Y "smtp" -T fields -e smtp.req.parameter',
                'tshark -r file.pcap -Y "imf" -T fields -e imf.from -e imf.to -e imf.subject'
            ],
            references: ['SMTP命令', 'MIME编码']
        },
        {
            id: 'icmp-analysis',
            category: 'protocol',
            title: 'ICMP协议分析',
            difficulty: 'easy',
            tags: ['ICMP', 'Ping', '隐写'],
            description: 'ICMP数据包分析，Ping扫描和数据隐藏',
            tsharkFilter: 'icmp',
            tsharkFields: ['frame.number', 'ip.src', 'ip.dst', 'icmp.type', 'data.data'],
            tips: [
                'ICMP data字段常隐藏Flag',
                '按序提取每个包的data转ASCII',
                '可能需要只看request或reply'
            ],
            commands: [
                'tshark -r file.pcap -Y "icmp" -T fields -e data.data | xxd -r -p',
                'tshark -r file.pcap -Y "icmp.type == 8" -T fields -e data.data'
            ],
            references: ['ICMP类型码', 'Ping隐写']
        },
        {
            id: 'telnet-analysis',
            category: 'protocol',
            title: 'Telnet协议分析',
            difficulty: 'easy',
            tags: ['Telnet', '远程登录', '明文'],
            description: 'Telnet明文协议分析，命令记录提取',
            tsharkFilter: 'telnet',
            tsharkFields: ['ip.src', 'ip.dst', 'telnet.data'],
            tips: [
                'Telnet是明文协议，Follow TCP Stream即可',
                '用户输入和服务器输出混在一起',
                '注意分辨发送方向'
            ],
            commands: [
                'tshark -r file.pcap -Y "telnet" -z "follow,tcp,ascii,0"'
            ],
            references: ['Telnet协议', 'TCP Stream跟踪']
        },

        // ========== 数据提取 ==========
        {
            id: 'file-extraction',
            category: 'extraction',
            title: '文件提取与恢复',
            difficulty: 'medium',
            tags: ['文件', '导出', 'HTTP'],
            description: '从HTTP、FTP、SMB等协议中提取传输的文件',
            tsharkFilter: 'http.content_type',
            tsharkFields: ['http.content_type', 'http.content_length', 'http.request.uri'],
            tips: [
                'Wireshark: File > Export Objects > HTTP',
                '使用foremost从原始数据分离文件',
                '注意分段传输的文件需要合并'
            ],
            commands: [
                'tshark -r file.pcap --export-objects http,./exported/',
                'tshark -r file.pcap --export-objects smb,./exported/'
            ],
            references: ['Foremost', 'Binwalk', 'File Carving']
        },
        {
            id: 'credential-extraction',
            category: 'extraction',
            title: '凭证信息提取',
            difficulty: 'medium',
            tags: ['密码', '凭证', '认证'],
            description: '从流量中提取用户名、密码、Token等敏感信息',
            tsharkFilter: 'http.authorization || ftp.request.command == "PASS" || http.cookie',
            tsharkFields: ['ip.src', 'http.authorization', 'http.cookie', 'ftp.request.arg'],
            tips: [
                'HTTP Basic Auth是Base64编码',
                '检查POST表单中的password字段',
                'Session Cookie可用于会话劫持'
            ],
            commands: [
                'tshark -r file.pcap -Y "http.authorization" -T fields -e http.authorization',
                'tshark -r file.pcap -Y "http.request.method == POST" -T fields -e http.file_data | grep -i pass'
            ],
            references: ['HTTP认证', 'Cookie安全']
        },
        {
            id: 'base64-extraction',
            category: 'extraction',
            title: 'Base64数据提取',
            difficulty: 'easy',
            tags: ['Base64', '编码', '解码'],
            description: '识别和解码流量中的Base64编码数据',
            tsharkFilter: 'http',
            tsharkFields: ['http.file_data', 'data.data'],
            tips: [
                'Base64特征: 大小写字母+数字+/=',
                '可能存在多层嵌套编码',
                '图片、文件常用Base64传输'
            ],
            commands: [
                'tshark -r file.pcap -T fields -e http.file_data | base64 -d',
                'echo "base64string" | base64 -d'
            ],
            references: ['Base64编码', 'URL编码']
        },
        {
            id: 'flag-search',
            category: 'extraction',
            title: 'Flag关键字搜索',
            difficulty: 'easy',
            tags: ['Flag', 'CTF', '搜索'],
            description: '在流量中直接搜索flag格式的字符串',
            tsharkFilter: 'frame contains "flag" || frame contains "FLAG" || frame contains "ctf"',
            tsharkFields: ['frame.number', 'ip.src', 'ip.dst'],
            tips: [
                '常见格式: flag{}, FLAG{}, ctf{}',
                '可能是分段的，需要拼接',
                '可能经过编码或加密'
            ],
            commands: [
                'strings file.pcap | grep -i "flag{"',
                'tshark -r file.pcap -Y "frame contains \\"flag\\"" -x'
            ],
            references: ['strings命令', 'grep正则']
        },

        // ========== 攻击识别 ==========
        {
            id: 'port-scan',
            category: 'attack',
            title: '端口扫描检测',
            difficulty: 'easy',
            tags: ['扫描', 'Nmap', '侦察'],
            description: '识别TCP/UDP端口扫描行为',
            tsharkFilter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
            tsharkFields: ['frame.time', 'ip.src', 'ip.dst', 'tcp.dstport'],
            tips: [
                'SYN扫描: 大量SYN包到不同端口',
                '统计每个目的端口的包数判断扫描',
                '检查RST回复判断端口开放状态'
            ],
            commands: [
                'tshark -r file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e tcp.dstport | sort | uniq -c | sort -rn',
                'tshark -r file.pcap -Y "tcp.flags.reset == 1" | wc -l'
            ],
            references: ['Nmap扫描类型', 'TCP三次握手']
        },
        {
            id: 'bruteforce',
            category: 'attack',
            title: '暴力破解检测',
            difficulty: 'medium',
            tags: ['爆破', '登录', '密码'],
            description: '识别SSH、FTP、HTTP登录暴力破解',
            tsharkFilter: 'http.request.method == "POST" || ftp.request.command == "PASS" || ssh',
            tsharkFields: ['frame.time', 'ip.src', 'http.request.uri', 'http.file_data'],
            tips: [
                '大量失败登录尝试',
                'HTTP 401/403响应码连续出现',
                '成功登录找最后一个200响应'
            ],
            commands: [
                'tshark -r file.pcap -Y "http.response.code == 401" | wc -l',
                'tshark -r file.pcap -Y "http.response.code == 200 && http.request.uri contains login"'
            ],
            references: ['HTTP状态码', 'SSH协议']
        },
        {
            id: 'sqli-detection',
            category: 'attack',
            title: 'SQL注入检测',
            difficulty: 'medium',
            tags: ['SQLi', 'Web攻击', '注入'],
            description: '识别SQL注入攻击流量',
            tsharkFilter: 'http.request.uri contains "select" || http.request.uri contains "union" || http.request.uri contains "\\x27"',
            tsharkFields: ['ip.src', 'http.request.uri', 'http.request.method'],
            tips: [
                '关键字: SELECT, UNION, OR 1=1, --',
                'URL编码: %27=单引号, %20=空格',
                '检查请求参数中的特殊字符'
            ],
            commands: [
                'tshark -r file.pcap -Y "http.request.uri matches \\"(select|union|insert|update|delete)\\"" -T fields -e http.request.full_uri',
                'tshark -r file.pcap -Y "http.request.uri contains \\"%27\\"" -T fields -e http.request.uri'
            ],
            references: ['SQL注入', 'OWASP Top 10']
        },
        {
            id: 'webshell-detection',
            category: 'attack',
            title: 'Webshell检测',
            difficulty: 'hard',
            tags: ['Webshell', '后门', '木马'],
            description: '识别Webshell上传和通信流量',
            tsharkFilter: 'http.request.method == "POST" && http.content_type contains "form"',
            tsharkFields: ['ip.src', 'http.request.uri', 'http.file_data', 'http.content_length'],
            tips: [
                '菜刀/冰蝎/哥斯拉有特定流量特征',
                '大量POST请求到同一脚本文件',
                '加密Webshell需要密钥解密'
            ],
            commands: [
                'tshark -r file.pcap -Y "http.request.method == POST && http.request.uri matches \\"\\\\.php$\\"" -T fields -e http.request.uri | sort | uniq -c',
                'tshark -r file.pcap -Y "http contains \\"@eval\\" || http contains \\"base64_decode\\"" -T fields -e http.file_data'
            ],
            references: ['冰蝎', '哥斯拉', '蚁剑']
        },
        {
            id: 'c2-detection',
            category: 'attack',
            title: 'C2通信检测',
            difficulty: 'hard',
            tags: ['C2', '命令控制', 'APT'],
            description: '识别恶意软件的命令控制通信',
            tsharkFilter: 'http.user_agent contains "Mozilla" && http.request.method == "POST"',
            tsharkFields: ['ip.dst', 'http.host', 'http.user_agent', 'http.request.uri'],
            tips: [
                '周期性通信(心跳包)',
                '异常User-Agent',
                '可疑域名或IP'
            ],
            commands: [
                'tshark -r file.pcap -Y "http" -T fields -e http.host | sort | uniq -c | sort -rn',
                'tshark -r file.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn | head -20'
            ],
            references: ['CobaltStrike', 'Metasploit']
        },

        // ========== 隐写术 ==========
        {
            id: 'icmp-stego',
            category: 'stego',
            title: 'ICMP隐写分析',
            difficulty: 'medium',
            tags: ['ICMP', '隐写', 'Ping'],
            description: 'ICMP数据字段中隐藏的信息提取',
            tsharkFilter: 'icmp.type == 8',
            tsharkFields: ['frame.number', 'ip.src', 'ip.dst', 'data.data', 'data.len'],
            tips: [
                '提取每个ICMP包的data字段',
                '可能每包一个字符需拼接',
                '注意区分请求和响应'
            ],
            commands: [
                'tshark -r file.pcap -Y "icmp.type == 8" -T fields -e data.data | tr -d "\\n" | xxd -r -p',
                'for i in $(tshark -r file.pcap -Y "icmp" -T fields -e data.data); do echo $i | xxd -r -p; done'
            ],
            references: ['Ping隐写', '数据编码']
        },
        {
            id: 'dns-tunnel',
            category: 'stego',
            title: 'DNS隧道检测',
            difficulty: 'hard',
            tags: ['DNS', '隧道', '隐蔽通道'],
            description: '检测通过DNS进行的隐蔽数据传输',
            tsharkFilter: 'dns.qry.name',
            tsharkFields: ['dns.qry.name', 'dns.qry.type', 'dns.txt'],
            tips: [
                '异常长的子域名(Base64/Hex)',
                '高频率DNS查询',
                'TXT记录携带大量数据'
            ],
            commands: [
                'tshark -r file.pcap -Y "dns.qry.type == 16" -T fields -e dns.txt',
                'tshark -r file.pcap -Y "dns" -T fields -e dns.qry.name | awk -F. \'{print length($1), $0}\' | sort -rn | head -20'
            ],
            references: ['DNS隧道工具', 'iodine', 'dnscat2']
        },
        {
            id: 'http-stego',
            category: 'stego',
            title: 'HTTP头部隐写',
            difficulty: 'medium',
            tags: ['HTTP', '隐写', 'Header'],
            description: '在HTTP头部字段中隐藏的数据',
            tsharkFilter: 'http',
            tsharkFields: ['http.request.line', 'http.response.line', 'http.cookie', 'http.x_headers'],
            tips: [
                '检查自定义X-头部',
                'Cookie值可能包含编码数据',
                '注意异常的Header字段'
            ],
            commands: [
                'tshark -r file.pcap -Y "http" -T fields -e http.request.line -e http.cookie',
                'tshark -r file.pcap -Y "http.response" -T fields -e http.response.line'
            ],
            references: ['HTTP头部', '隐蔽通道']
        },

        // ========== 加密解密 ==========
        {
            id: 'tls-decrypt',
            category: 'crypto',
            title: 'TLS/SSL流量解密',
            difficulty: 'hard',
            tags: ['TLS', 'SSL', 'HTTPS', '解密'],
            description: '使用私钥或SSLKEYLOGFILE解密TLS流量',
            tsharkFilter: 'tls',
            tsharkFields: ['tls.handshake.type', 'tls.record.content_type', 'tls.handshake.ciphersuite'],
            tips: [
                '需要服务器私钥(.pem)或会话密钥日志',
                '只有非PFS(非DHE/ECDHE)可用私钥解密',
                'TLS 1.3必须使用SSLKEYLOGFILE'
            ],
            commands: [
                'tshark -r file.pcap -o "tls.keys_list:192.168.1.1,443,http,server.pem"',
                'editcap --inject-secrets tls,sslkeylog.txt input.pcap decrypted.pcapng'
            ],
            references: ['Wireshark TLS解密', 'SSLKEYLOGFILE']
        },
        {
            id: 'weak-crypto',
            category: 'crypto',
            title: '弱加密识别',
            difficulty: 'hard',
            tags: ['加密', 'RSA', '弱密钥'],
            description: '识别可破解的弱加密和密钥',
            tsharkFilter: 'tls.handshake.ciphersuite',
            tsharkFields: ['tls.handshake.ciphersuite', 'tls.handshake.certificate'],
            tips: [
                '检查是否使用弱密码套件',
                'RSA密钥可能可分解',
                '老旧TLS版本可能有漏洞'
            ],
            commands: [
                'tshark -r file.pcap -Y "tls.handshake.type == 11" -T fields -e tls.handshake.certificate',
                'openssl x509 -in cert.pem -text -noout'
            ],
            references: ['密码套件', 'RSA因式分解']
        },

        // ========== 无线安全 ==========
        {
            id: 'wifi-crack',
            category: 'wireless',
            title: 'WiFi密码破解',
            difficulty: 'hard',
            tags: ['WiFi', 'WPA', 'Aircrack'],
            description: '使用握手包破解WPA/WPA2密码',
            tsharkFilter: 'eapol',
            tsharkFields: ['wlan.sa', 'wlan.da', 'eapol.keydes.type'],
            tips: [
                '需要捕获四次握手(EAPOL)',
                '使用aircrack-ng配合字典破解',
                'hashcat可进行GPU加速'
            ],
            commands: [
                'tshark -r file.pcap -Y "eapol"',
                'aircrack-ng -w wordlist.txt -b <BSSID> capture.cap'
            ],
            references: ['Aircrack-ng', 'hashcat', 'PMKID攻击']
        },
        {
            id: 'bluetooth',
            category: 'wireless',
            title: '蓝牙流量分析',
            difficulty: 'medium',
            tags: ['蓝牙', 'OBEX', '无线'],
            description: '蓝牙协议分析和文件传输提取',
            tsharkFilter: 'bthci || btl2cap || btrfcomm || btobex',
            tsharkFields: ['bthci.evt.status', 'btobex.name', 'btobex.type'],
            tips: [
                'OBEX协议用于文件传输',
                '可导出传输的文件',
                '检查设备配对信息'
            ],
            commands: [
                'tshark -r file.pcap -Y "btobex" -T fields -e btobex.name',
                'tshark -r file.pcap --export-objects btobex,./bluetooth/'
            ],
            references: ['蓝牙协议', 'OBEX']
        },

        // ========== 取证分析 ==========
        {
            id: 'timeline',
            category: 'forensics',
            title: '时间线分析',
            difficulty: 'medium',
            tags: ['时间线', '取证', '溯源'],
            description: '根据时间戳重建攻击事件时间线',
            tsharkFilter: '',
            tsharkFields: ['frame.time', 'frame.time_relative', 'ip.src', 'ip.dst'],
            tips: [
                '按时间排序分析事件顺序',
                '关注异常时间间隔',
                '结合多个数据源交叉验证'
            ],
            commands: [
                'tshark -r file.pcap -T fields -e frame.time -e ip.src -e ip.dst | head -100',
                'capinfos file.pcap'
            ],
            references: ['时间线分析', '事件关联']
        },
        {
            id: 'statistics',
            category: 'forensics',
            title: '流量统计分析',
            difficulty: 'easy',
            tags: ['统计', '概览', '基础'],
            description: '流量包整体统计和协议分布分析',
            tsharkFilter: '',
            tsharkFields: [],
            tips: [
                '先看协议层级统计',
                '识别异常流量比例',
                '关注通信最多的IP对'
            ],
            commands: [
                'tshark -r file.pcap -q -z io,phs',
                'tshark -r file.pcap -q -z conv,ip',
                'tshark -r file.pcap -q -z endpoints,ip'
            ],
            references: ['Wireshark统计', 'IO图表']
        },
        {
            id: 'pcap-repair',
            category: 'forensics',
            title: '流量包修复',
            difficulty: 'medium',
            tags: ['修复', 'pcap', '损坏'],
            description: '修复损坏或异常的pcap文件',
            tsharkFilter: '',
            tsharkFields: [],
            tips: [
                '检查文件头魔数',
                '使用pcapfix修复',
                '手动修复需要了解pcap格式'
            ],
            commands: [
                'pcapfix -o fixed.pcap damaged.pcap',
                'xxd file.pcap | head -5',
                'capinfos file.pcap'
            ],
            references: ['pcapfix', 'pcap格式', 'pcapng格式']
        },

        // ========== 特殊协议 ==========
        {
            id: 'usb-keyboard',
            category: 'special',
            title: 'USB键盘流量分析',
            difficulty: 'medium',
            tags: ['USB', '键盘', 'HID'],
            description: '从USB流量中恢复键盘输入',
            tsharkFilter: 'usb.transfer_type == 0x01 && usb.data_len == 8',
            tsharkFields: ['usb.capdata', 'usbhid.data'],
            tips: [
                '键盘数据通常8字节',
                '第三字节是按键码',
                '需要脚本解析还原按键'
            ],
            commands: [
                'tshark -r file.pcap -Y "usb.transfer_type == 0x01" -T fields -e usbhid.data | grep -v "^$"',
                'python usb_keyboard_decoder.py'
            ],
            references: ['USB HID', '键盘扫描码']
        },
        {
            id: 'usb-mouse',
            category: 'special',
            title: 'USB鼠标流量分析',
            difficulty: 'medium',
            tags: ['USB', '鼠标', 'HID'],
            description: '从USB流量中恢复鼠标轨迹',
            tsharkFilter: 'usb.transfer_type == 0x01',
            tsharkFields: ['usb.capdata', 'usbhid.data'],
            tips: [
                '鼠标数据含X/Y位移和按键',
                '可还原鼠标移动轨迹',
                '结合图像可能绘制出信息'
            ],
            commands: [
                'tshark -r file.pcap -Y "usb.transfer_type == 0x01" -T fields -e usbhid.data',
                'python usb_mouse_decoder.py'
            ],
            references: ['USB HID', '鼠标轨迹恢复']
        },
        {
            id: 'modbus',
            category: 'special',
            title: '工控Modbus分析',
            difficulty: 'hard',
            tags: ['工控', 'Modbus', 'SCADA'],
            description: 'Modbus工业控制协议分析',
            tsharkFilter: 'mbtcp || modbus',
            tsharkFields: ['mbtcp.trans_id', 'modbus.func_code', 'modbus.data'],
            tips: [
                '关注功能码和寄存器操作',
                '写操作可能是攻击命令',
                '检查异常的寄存器值'
            ],
            commands: [
                'tshark -r file.pcap -Y "modbus" -T fields -e modbus.func_code -e modbus.data',
                'tshark -r file.pcap -Y "modbus.func_code == 6"'
            ],
            references: ['Modbus协议', '工控安全']
        }
    ]
};

// 导出知识库
if (typeof module !== 'undefined' && module.exports) {
    module.exports = knowledgeBase;
}
