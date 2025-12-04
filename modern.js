/**
 * TShark Gen - Modern UI Logic
 */

// ===== State Management =====
const state = {
    tsharkPath: 'tshark',
    inputSource: 'file',
    inputFile: 'capture.pcap',
    inputInterface: '',
    promiscuous: false,
    monitor: false,

    displayFilter: '',
    selectedProtocols: [],
    srcIp: '',
    dstIp: '',
    port: '',
    containsKeyword: '',
    customFilter: '',
    filterLogic: 'and',

    outputFormat: 'default',
    selectedFields: [],
    separator: ',',
    includeHeader: true,
    verbose: false,
    quiet: false,
    noResolve: false,

    statistics: [],
    tcpStream: '',

    twoPass: false,
    packetCount: '',
    outputFile: '',
    decodeAs: ''
};

// ===== Scenario Presets (CTF流量取证题型) =====
const scenarios = {
    // === 一、基础分析 ===
    protocol: {
        name: '协议分布',
        category: 'basic',
        config: { quiet: true, statistics: ['io,phs'] }
    },
    ipconv: {
        name: 'IP通信对',
        category: 'basic',
        config: { quiet: true, statistics: ['conv,ip'] }
    },
    tcpconv: {
        name: 'TCP会话',
        category: 'basic',
        config: { quiet: true, statistics: ['conv,tcp'] }
    },
    endpoints: {
        name: '端点统计',
        category: 'basic',
        config: { quiet: true, statistics: ['endpoints,ip'] }
    },
    timeline: {
        name: '时间线',
        category: 'basic',
        config: {
            outputFormat: 'fields',
            selectedFields: ['frame.time', 'ip.src', 'ip.dst', 'frame.protocols', 'frame.len']
        }
    },
    expert: {
        name: '专家分析',
        category: 'basic',
        config: { quiet: true, statistics: ['expert'] }
    },

    // === 二、HTTP/Web分析 ===
    http: {
        name: 'HTTP请求',
        category: 'web',
        config: {
            selectedProtocols: ['http.request'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.request.uri', 'http.request.method']
        }
    },
    httpResponse: {
        name: 'HTTP响应',
        category: 'web',
        config: {
            selectedProtocols: ['http.response'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.response.code', 'http.content_type', 'http.content_length']
        }
    },
    useragent: {
        name: 'User-Agent',
        category: 'web',
        config: {
            selectedProtocols: ['http.user_agent'],
            outputFormat: 'fields',
            selectedFields: ['ip.src', 'http.host', 'http.user_agent']
        }
    },
    cookies: {
        name: 'Cookies',
        category: 'web',
        config: {
            selectedProtocols: ['http.cookie'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.cookie']
        }
    },
    post: {
        name: 'POST数据',
        category: 'web',
        config: {
            customFilter: 'http.request.method == "POST"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.request.uri', 'http.file_data']
        }
    },
    httpAuth: {
        name: 'HTTP认证',
        category: 'web',
        config: {
            customFilter: 'http.authorization || http.www_authenticate',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.authorization', 'http.www_authenticate']
        }
    },
    webUpload: {
        name: '文件上传',
        category: 'web',
        config: {
            customFilter: 'http.content_type contains "multipart" || http.request.uri contains "upload"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.request.uri', 'http.content_type']
        }
    },
    webshell: {
        name: 'Webshell检测',
        category: 'web',
        config: {
            customFilter: 'http.request.uri contains ".php" && (http contains "cmd" || http contains "shell" || http contains "eval" || http contains "base64")',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.request.uri', 'http.file_data']
        }
    },
    sqli: {
        name: 'SQL注入',
        category: 'web',
        config: {
            customFilter: 'http.request.uri contains "select" || http.request.uri contains "union" || http contains "SQL syntax"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.request.uri']
        }
    },

    // === 三、凭据与敏感信息 ===
    credentials: {
        name: 'FTP凭据',
        category: 'credentials',
        config: {
            customFilter: 'ftp.request.command == "USER" || ftp.request.command == "PASS"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'ftp.request.command', 'ftp.request.arg']
        }
    },
    telnet: {
        name: 'Telnet会话',
        category: 'credentials',
        config: {
            selectedProtocols: ['telnet'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'telnet.data']
        }
    },
    smtp: {
        name: 'SMTP邮件',
        category: 'credentials',
        config: {
            selectedProtocols: ['smtp'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'smtp.req.command', 'smtp.req.parameter']
        }
    },
    imapPop: {
        name: 'IMAP/POP3',
        category: 'credentials',
        config: {
            customFilter: 'imap || pop',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'imap.request', 'pop.request.command']
        }
    },
    basicAuth: {
        name: 'Basic认证',
        category: 'credentials',
        config: {
            customFilter: 'http.authorization contains "Basic"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.authorization']
        }
    },
    flagSearch: {
        name: 'Flag搜索',
        category: 'credentials',
        config: {
            containsKeyword: 'flag',
            outputFormat: 'default'
        }
    },

    // === 四、DNS分析 ===
    dns: {
        name: 'DNS查询',
        category: 'dns',
        config: {
            selectedProtocols: ['dns.qry.name'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'dns.qry.name', 'dns.a']
        }
    },
    dnsStats: {
        name: 'DNS统计',
        category: 'dns',
        config: { quiet: true, statistics: ['dns,tree'] }
    },
    dnsTunnel: {
        name: 'DNS隧道',
        category: 'dns',
        config: {
            customFilter: 'dns.qry.name && frame.len > 100',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'dns.qry.name', 'dns.qry.type', 'frame.len']
        }
    },
    dnsExfil: {
        name: 'DNS外传',
        category: 'dns',
        config: {
            customFilter: 'dns.qry.type == 16 || dns.qry.type == 28',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'dns.qry.name', 'dns.txt', 'dns.aaaa']
        }
    },

    // === 五、隐写与数据提取 ===
    icmpData: {
        name: 'ICMP数据',
        category: 'stego',
        config: {
            selectedProtocols: ['icmp'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'icmp.type', 'data.data']
        }
    },
    tcpPayload: {
        name: 'TCP载荷',
        category: 'stego',
        config: {
            customFilter: 'tcp.payload',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.payload']
        }
    },
    base64Data: {
        name: 'Base64数据',
        category: 'stego',
        config: {
            containsKeyword: 'base64',
            outputFormat: 'default'
        }
    },
    hexData: {
        name: '十六进制',
        category: 'stego',
        config: {
            customFilter: 'data.data',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'data.data']
        }
    },

    // === 六、攻击检测 ===
    portScan: {
        name: '端口扫描',
        category: 'attack',
        config: {
            customFilter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
            quiet: true,
            statistics: ['conv,ip']
        }
    },
    synFlood: {
        name: 'SYN洪泛',
        category: 'attack',
        config: {
            customFilter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'tcp.dstport']
        }
    },
    bruteforce: {
        name: '暴力破解',
        category: 'attack',
        config: {
            customFilter: 'http.response.code == 401 || ftp.response.code == 530 || ssh',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.response.code', 'ftp.response.code']
        }
    },
    c2: {
        name: 'C2通信',
        category: 'attack',
        config: {
            customFilter: 'http.request.method == "POST" && frame.len < 500',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.host', 'http.request.uri']
        }
    },
    malwareDns: {
        name: '恶意域名',
        category: 'attack',
        config: {
            customFilter: 'dns.qry.name contains ".tk" || dns.qry.name contains ".top" || dns.qry.name matches "^[a-z]{20,}"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'dns.qry.name', 'dns.a']
        }
    },

    // === 七、流追踪类 ===
    tcpstream: {
        name: 'TCP流0',
        category: 'stream',
        config: { quiet: true, tcpStream: '0' }
    },
    httpObjects: {
        name: 'HTTP对象',
        category: 'stream',
        config: { quiet: true, statistics: ['http,tree'] }
    },
    ftpData: {
        name: 'FTP数据',
        category: 'stream',
        config: {
            selectedProtocols: ['ftp-data'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'ftp-data.command']
        }
    },
    smbFiles: {
        name: 'SMB文件',
        category: 'stream',
        config: {
            customFilter: 'smb2.filename || smb.file',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'smb2.filename', 'smb.file']
        }
    },

    // === 八、TLS/加密流量 ===
    tlsHandshake: {
        name: 'TLS握手',
        category: 'tls',
        config: {
            customFilter: 'tls.handshake',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'tls.handshake.type', 'tls.handshake.extensions_server_name']
        }
    },
    tlsSni: {
        name: 'TLS SNI',
        category: 'tls',
        config: {
            customFilter: 'tls.handshake.extensions_server_name',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'tls.handshake.extensions_server_name']
        }
    },
    sshTraffic: {
        name: 'SSH流量',
        category: 'tls',
        config: {
            selectedProtocols: ['ssh'],
            quiet: true,
            statistics: ['conv,tcp']
        }
    },

    // === 九、加密Webshell检测 ===
    behinder: {
        name: '冰蝎检测',
        category: 'webshell',
        config: {
            customFilter: 'http.request.method == "POST" && http.content_type contains "application/x-www-form-urlencoded" && http.content_length > 500',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.host', 'http.request.uri', 'http.content_length']
        }
    },
    godzilla: {
        name: '哥斯拉检测',
        category: 'webshell',
        config: {
            customFilter: 'http.request.method == "POST" && (http.request.uri contains ".php" || http.request.uri contains ".jsp" || http.request.uri contains ".aspx")',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.host', 'http.request.uri', 'http.content_length', 'http.response.code']
        }
    },
    antsword: {
        name: '蚁剑检测',
        category: 'webshell',
        config: {
            customFilter: 'http.request.method == "POST" && http contains "@ini_set"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.host', 'http.request.uri', 'http.file_data']
        }
    },
    shellPHP: {
        name: 'PHP一句话',
        category: 'webshell',
        config: {
            customFilter: 'http contains "eval" || http contains "assert" || http contains "base64_decode" || http contains "system("',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.request.uri', 'http.file_data']
        }
    },
    shellJSP: {
        name: 'JSP马检测',
        category: 'webshell',
        config: {
            customFilter: 'http.request.uri contains ".jsp" && http.request.method == "POST"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.request.uri', 'http.content_length']
        }
    },
    shellASP: {
        name: 'ASP马检测',
        category: 'webshell',
        config: {
            customFilter: '(http.request.uri contains ".asp" || http.request.uri contains ".aspx") && http.request.method == "POST"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.request.uri', 'http.content_length']
        }
    },
    cobaltstrike: {
        name: 'CobaltStrike',
        category: 'webshell',
        config: {
            customFilter: 'http.request.uri matches "^/[a-zA-Z]{4}$" || http.cookie contains "SESSIONID"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'http.host', 'http.request.uri', 'http.cookie']
        }
    }
};

// ===== DOM Elements =====
const elements = {};

// ===== Initialization =====
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    cacheElements();
    bindEvents();
    loadSettings();
    generateCommand();
    initAI();
});

function initTabs() {
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            // Remove active class
            navItems.forEach(nav => nav.classList.remove('active'));
            tabContents.forEach(tab => tab.classList.remove('active'));

            // Add active class
            item.classList.add('active');
            const tabId = `tab-${item.dataset.tab}`;
            document.getElementById(tabId).classList.add('active');
        });
    });
}

function cacheElements() {
    // TShark path
    elements.tsharkPath = document.getElementById('tsharkPath');

    // Input source
    elements.inputSourceRadios = document.querySelectorAll('input[name="inputSource"]');
    elements.fileInputGroup = document.getElementById('fileInputGroup');
    elements.interfaceInputGroup = document.getElementById('interfaceInputGroup');
    elements.inputFile = document.getElementById('inputFile');
    elements.inputInterface = document.getElementById('inputInterface');
    elements.promiscuous = document.getElementById('promiscuous');
    elements.monitor = document.getElementById('monitor');

    // Filters
    elements.protoChips = document.querySelectorAll('.proto-chip');
    elements.srcIp = document.getElementById('srcIp');
    elements.dstIp = document.getElementById('dstIp');
    elements.port = document.getElementById('port');
    elements.containsKeyword = document.getElementById('containsKeyword');
    elements.customFilter = document.getElementById('customFilter');
    elements.filterLogicRadios = document.querySelectorAll('input[name="filterLogic"]');

    // Output
    elements.outputFormatRadios = document.querySelectorAll('input[name="outputFormat"]');
    elements.fieldsOptions = document.getElementById('fieldsOptions');
    elements.fieldCheckboxes = document.querySelectorAll('.field-check input');
    elements.customField = document.getElementById('customField');
    elements.separator = document.getElementById('separator');
    elements.includeHeader = document.getElementById('includeHeader');
    elements.verbose = document.getElementById('verbose');
    elements.quiet = document.getElementById('quiet');
    elements.noResolve = document.getElementById('noResolve');

    // Statistics
    elements.statOptions = document.querySelectorAll('.stat-option');
    elements.tcpStream = document.getElementById('tcpStream');

    // Advanced
    elements.twoPass = document.getElementById('twoPass');
    elements.packetCount = document.getElementById('packetCount');
    elements.outputFile = document.getElementById('outputFile');
    elements.decodeAs = document.getElementById('decodeAs');

    // Scenarios
    elements.scenarioCards = document.querySelectorAll('.scenario-card');

    // Actions
    elements.resetAll = document.getElementById('resetAll');
    elements.copyCmd = document.getElementById('copyCmd');
    elements.downloadScript = document.getElementById('downloadScript');
    elements.commandOutput = document.getElementById('commandOutput');
    elements.copyToast = document.getElementById('copyToast');

    // Run command
    elements.runCmd = document.getElementById('runCmd');
    elements.resultModal = document.getElementById('resultModal');
    elements.resultOutput = document.getElementById('resultOutput');
    elements.resultStatus = document.getElementById('resultStatus');
    elements.resultTitle = document.getElementById('resultTitle');
    elements.closeResultModal = document.getElementById('closeResultModal');
    elements.copyResult = document.getElementById('copyResult');

    // Knowledge base
    elements.knowledgeSearch = document.getElementById('knowledgeSearch');
    elements.knowledgeCategories = document.getElementById('knowledgeCategories');
    elements.knowledgeList = document.getElementById('knowledgeList');
    elements.knowledgeDetail = document.getElementById('knowledgeDetail');
    elements.closeDetail = document.getElementById('closeDetail');
    elements.applyKnowledge = document.getElementById('applyKnowledge');
}

function bindEvents() {
    // TShark path
    elements.tsharkPath.addEventListener('input', (e) => {
        state.tsharkPath = e.target.value || 'tshark';
        localStorage.setItem('tshark-path', state.tsharkPath);
        generateCommand();
    });

    // Input source toggle
    elements.inputSourceRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            state.inputSource = e.target.value;
            // Update UI for toggle cards
            document.querySelectorAll('.toggle-option').forEach(opt => {
                opt.classList.toggle('active', opt.querySelector('input').checked);
            });
            toggleInputGroups();
            generateCommand();
        });
    });

    // Input fields
    elements.inputFile.addEventListener('input', (e) => {
        state.inputFile = e.target.value;
        generateCommand();
    });

    elements.inputInterface.addEventListener('input', (e) => {
        state.inputInterface = e.target.value;
        generateCommand();
    });

    elements.promiscuous.addEventListener('change', (e) => {
        state.promiscuous = e.target.checked;
        generateCommand();
    });

    elements.monitor.addEventListener('change', (e) => {
        state.monitor = e.target.checked;
        generateCommand();
    });

    // Protocol chips
    elements.protoChips.forEach(chip => {
        chip.addEventListener('click', () => {
            chip.classList.toggle('active');
            updateSelectedProtocols();
            generateCommand();
        });
    });

    // Filter inputs
    ['srcIp', 'dstIp', 'port', 'containsKeyword', 'customFilter'].forEach(id => {
        elements[id].addEventListener('input', (e) => {
            state[id] = e.target.value;
            generateCommand();
        });
    });

    elements.filterLogicRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            state.filterLogic = e.target.value;
            generateCommand();
        });
    });

    // Output format
    elements.outputFormatRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            state.outputFormat = e.target.value;
            toggleFieldsOptions();
            generateCommand();
        });
    });

    // Field checkboxes
    elements.fieldCheckboxes.forEach(cb => {
        cb.addEventListener('change', () => {
            updateSelectedFields();
            generateCommand();
        });
    });

    // Custom field
    elements.customField.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && e.target.value.trim()) {
            addCustomField(e.target.value.trim());
            e.target.value = '';
            generateCommand();
        }
    });

    elements.separator.addEventListener('change', (e) => {
        state.separator = e.target.value;
        generateCommand();
    });

    elements.includeHeader.addEventListener('change', (e) => {
        state.includeHeader = e.target.checked;
        generateCommand();
    });

    // Output options
    elements.verbose.addEventListener('change', (e) => {
        state.verbose = e.target.checked;
        generateCommand();
    });

    elements.quiet.addEventListener('change', (e) => {
        state.quiet = e.target.checked;
        generateCommand();
    });

    elements.noResolve.addEventListener('change', (e) => {
        state.noResolve = e.target.checked;
        generateCommand();
    });

    // Statistics
    elements.statOptions.forEach(cb => {
        cb.addEventListener('change', () => {
            updateSelectedStats();
            generateCommand();
        });
    });

    elements.tcpStream.addEventListener('input', (e) => {
        state.tcpStream = e.target.value;
        generateCommand();
    });

    // Advanced options
    elements.twoPass.addEventListener('change', (e) => {
        state.twoPass = e.target.checked;
        generateCommand();
    });

    elements.packetCount.addEventListener('input', (e) => {
        state.packetCount = e.target.value;
        generateCommand();
    });

    elements.outputFile.addEventListener('input', (e) => {
        state.outputFile = e.target.value;
        generateCommand();
    });

    elements.decodeAs.addEventListener('input', (e) => {
        state.decodeAs = e.target.value;
        generateCommand();
    });

    // Scenario cards
    elements.scenarioCards.forEach(card => {
        card.addEventListener('click', () => {
            applyScenario(card.dataset.scenario);
        });
    });

    // Actions
    elements.resetAll.addEventListener('click', resetAll);
    elements.copyCmd.addEventListener('click', copyCommand);
    elements.downloadScript.addEventListener('click', downloadScript);

    // Run command
    if (elements.runCmd) {
        elements.runCmd.addEventListener('click', runCommand);
    }
    if (elements.closeResultModal) {
        elements.closeResultModal.addEventListener('click', closeResultModal);
        elements.resultModal.querySelector('.modal-overlay').addEventListener('click', closeResultModal);
    }
    if (elements.copyResult) {
        elements.copyResult.addEventListener('click', copyResult);
    }
}

// ===== UI Functions =====
function toggleInputGroups() {
    if (state.inputSource === 'file') {
        elements.fileInputGroup.classList.remove('hidden');
        elements.interfaceInputGroup.classList.add('hidden');
    } else {
        elements.fileInputGroup.classList.add('hidden');
        elements.interfaceInputGroup.classList.remove('hidden');
    }
}

function toggleFieldsOptions() {
    if (state.outputFormat === 'fields') {
        elements.fieldsOptions.classList.remove('hidden');
    } else {
        elements.fieldsOptions.classList.add('hidden');
    }
}

function updateSelectedProtocols() {
    state.selectedProtocols = [];
    elements.protoChips.forEach(chip => {
        if (chip.classList.contains('active')) {
            state.selectedProtocols.push(chip.dataset.filter);
        }
    });
}

function updateSelectedFields() {
    state.selectedFields = [];
    elements.fieldCheckboxes.forEach(cb => {
        if (cb.checked) {
            state.selectedFields.push(cb.value);
        }
    });
}

function updateSelectedStats() {
    state.statistics = [];
    elements.statOptions.forEach(cb => {
        if (cb.checked) {
            state.statistics.push(cb.value);
        }
    });
}

function addCustomField(field) {
    if (!state.selectedFields.includes(field)) {
        state.selectedFields.push(field);
    }
}

// ===== Scenario Functions =====
function applyScenario(scenarioKey) {
    const scenario = scenarios[scenarioKey];
    if (!scenario) return;

    // Reset relevant state
    resetFiltersAndOptions();

    // Apply scenario config
    const config = scenario.config;

    if (config.selectedProtocols) {
        state.selectedProtocols = [...config.selectedProtocols];
        elements.protoChips.forEach(chip => {
            if (config.selectedProtocols.includes(chip.dataset.filter)) {
                chip.classList.add('active');
            } else {
                chip.classList.remove('active');
            }
        });
    }

    if (config.customFilter) {
        state.customFilter = config.customFilter;
        elements.customFilter.value = config.customFilter;
    }

    if (config.outputFormat) {
        state.outputFormat = config.outputFormat;
        elements.outputFormatRadios.forEach(radio => {
            radio.checked = radio.value === config.outputFormat;
        });
        toggleFieldsOptions();
    }

    if (config.selectedFields) {
        state.selectedFields = [...config.selectedFields];
        elements.fieldCheckboxes.forEach(cb => {
            cb.checked = config.selectedFields.includes(cb.value);
        });
    }

    if (config.quiet !== undefined) {
        state.quiet = config.quiet;
        elements.quiet.checked = config.quiet;
    }

    if (config.statistics) {
        state.statistics = [...config.statistics];
        elements.statOptions.forEach(cb => {
            cb.checked = config.statistics.includes(cb.value);
        });
    }

    if (config.tcpStream !== undefined) {
        state.tcpStream = config.tcpStream;
        elements.tcpStream.value = config.tcpStream;
    }

    // Highlight active scenario
    elements.scenarioCards.forEach(card => {
        card.classList.remove('active');
    });
    document.querySelector(`[data-scenario="${scenarioKey}"]`)?.classList.add('active');

    // Switch to relevant tab if needed (optional)

    generateCommand();
}

function resetFiltersAndOptions() {
    state.selectedProtocols = [];
    state.srcIp = '';
    state.dstIp = '';
    state.port = '';
    state.containsKeyword = '';
    state.customFilter = '';
    state.outputFormat = 'default';
    state.selectedFields = [];
    state.verbose = false;
    state.quiet = false;
    state.statistics = [];
    state.tcpStream = '';

    // Reset UI
    elements.protoChips.forEach(chip => chip.classList.remove('active'));
    elements.srcIp.value = '';
    elements.dstIp.value = '';
    elements.port.value = '';
    elements.containsKeyword.value = '';
    elements.customFilter.value = '';
    elements.outputFormatRadios.forEach(radio => radio.checked = radio.value === 'default');
    elements.fieldCheckboxes.forEach(cb => cb.checked = false);
    elements.verbose.checked = false;
    elements.quiet.checked = false;
    elements.statOptions.forEach(cb => cb.checked = false);
    elements.tcpStream.value = '';

    toggleFieldsOptions();
}

// ===== Run Command Functions =====
const API_BASE = 'http://localhost:8765';

async function runCommand(event) {
    // 阻止默认行为和事件冒泡
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }

    console.log('runCommand called');

    const command = state.generatedCommand;
    if (!command) {
        showToast('请先生成命令');
        return;
    }

    console.log('Executing command:', command);

    // 显示结果模态框
    if (!elements.resultModal) {
        console.error('resultModal not found');
        showToast('结果窗口未找到');
        return;
    }

    elements.resultModal.classList.remove('hidden');
    elements.resultOutput.textContent = '正在执行命令...\n\n' + command;
    elements.resultStatus.textContent = '运行中';
    elements.resultStatus.className = 'status-badge running';
    elements.runCmd.disabled = true;

    try {
        console.log('Fetching:', `${API_BASE}/api/run`);
        const response = await fetch(`${API_BASE}/api/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command })
        });

        const result = await response.json();
        console.log('Result:', result);

        if (result.success) {
            elements.resultOutput.textContent = result.output || '(无输出)';
            elements.resultStatus.textContent = '完成';
            elements.resultStatus.className = 'status-badge success';
        } else {
            elements.resultOutput.textContent = `错误: ${result.error}\n\n${result.output || ''}`;
            elements.resultStatus.textContent = '失败';
            elements.resultStatus.className = 'status-badge error';
        }
    } catch (err) {
        console.error('Fetch error:', err);
        elements.resultOutput.textContent = `连接失败: ${err.message}\n\n请确保后端服务已启动:\ncd backend && python server.py`;
        elements.resultStatus.textContent = '连接失败';
        elements.resultStatus.className = 'status-badge error';
    } finally {
        elements.runCmd.disabled = false;
    }
}

function closeResultModal() {
    elements.resultModal.classList.add('hidden');
}

function copyResult() {
    const text = elements.resultOutput.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('结果已复制');
    });
}

// ===== Command Generation =====
function generateCommand() {
    let cmd = escapeArg(state.tsharkPath);

    // Input source
    if (state.inputSource === 'file' && state.inputFile) {
        cmd += ` -r ${escapeArg(state.inputFile)}`;
    } else if (state.inputSource === 'interface' && state.inputInterface) {
        cmd += ` -i ${escapeArg(state.inputInterface)}`;
    }

    // Capture options
    if (state.promiscuous) cmd += ' -p';
    if (state.monitor) cmd += ' -I';

    // Two-pass analysis
    if (state.twoPass) cmd += ' -2';

    // Name resolution
    if (state.noResolve) cmd += ' -n';

    // Display filter
    const filter = buildDisplayFilter();
    if (filter) {
        cmd += ` -Y "${filter}"`;
    }

    // Quiet mode
    if (state.quiet) cmd += ' -q';

    // Verbose mode
    if (state.verbose) cmd += ' -V';

    // Output format
    if (state.outputFormat === 'fields') {
        cmd += ' -T fields';
        state.selectedFields.forEach(field => {
            cmd += ` -e ${field}`;
        });
        if (state.selectedFields.length > 0) {
            const sep = state.separator === '\\t' ? '\\t' : state.separator;
            cmd += ` -E separator=${sep === ',' ? ',' : `'${sep}'`}`;
            if (state.includeHeader) {
                cmd += ' -E header=y';
            }
        }
    } else if (state.outputFormat === 'json') {
        cmd += ' -T json';
    } else if (state.outputFormat === 'pdml') {
        cmd += ' -T pdml';
    }

    // Statistics
    state.statistics.forEach(stat => {
        cmd += ` -z ${stat}`;
    });

    // TCP stream follow
    if (state.tcpStream !== '') {
        cmd += ` -z follow,tcp,ascii,${state.tcpStream}`;
    }

    // Packet count
    if (state.packetCount) {
        cmd += ` -c ${state.packetCount}`;
    }

    // Output file
    if (state.outputFile) {
        cmd += ` -w ${escapeArg(state.outputFile)}`;
    }

    // Decode As
    if (state.decodeAs) {
        cmd += ` -d ${escapeArg(state.decodeAs)}`;
    }

    elements.commandOutput.textContent = cmd;
}

function buildDisplayFilter() {
    const conditions = [];

    // Protocol filters
    state.selectedProtocols.forEach(proto => {
        conditions.push(proto);
    });

    // IP filters
    if (state.srcIp) {
        conditions.push(`ip.src == ${state.srcIp}`);
    }
    if (state.dstIp) {
        conditions.push(`ip.dst == ${state.dstIp}`);
    }

    // Port filter
    if (state.port) {
        conditions.push(`tcp.port == ${state.port} || udp.port == ${state.port}`);
    }

    // Keyword filter
    if (state.containsKeyword) {
        conditions.push(`frame contains "${state.containsKeyword}"`);
    }

    // Custom filter
    if (state.customFilter) {
        conditions.push(`(${state.customFilter})`);
    }

    if (conditions.length === 0) return '';

    const logic = state.filterLogic === 'and' ? ' && ' : ' || ';
    return conditions.join(logic);
}

function escapeArg(arg) {
    if (arg.includes(' ') || arg.includes('"') || arg.includes("'")) {
        return `"${arg.replace(/"/g, '\\"')}"`;
    }
    return arg;
}

// ===== Actions =====
function copyCommand() {
    const cmd = elements.commandOutput.textContent;
    navigator.clipboard.writeText(cmd).then(() => {
        showToast();
    }).catch(err => {
        console.error('Failed to copy:', err);
        const textarea = document.createElement('textarea');
        textarea.value = cmd;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast();
    });
}

function showToast() {
    elements.copyToast.classList.add('show');
    setTimeout(() => {
        elements.copyToast.classList.remove('show');
    }, 2000);
}

function downloadScript() {
    const cmd = elements.commandOutput.textContent;
    const script = `#!/bin/bash
# TShark 命令脚本
# 生成时间: ${new Date().toLocaleString('zh-CN')}

${cmd}
`;

    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'tshark_command.sh';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function resetAll() {
    const savedPath = state.tsharkPath;
    Object.assign(state, {
        tsharkPath: savedPath,
        inputSource: 'file',
        inputFile: 'capture.pcap',
        inputInterface: '',
        promiscuous: false,
        monitor: false,
        displayFilter: '',
        selectedProtocols: [],
        srcIp: '',
        dstIp: '',
        port: '',
        containsKeyword: '',
        customFilter: '',
        filterLogic: 'and',
        outputFormat: 'default',
        selectedFields: [],
        separator: ',',
        includeHeader: true,
        verbose: false,
        quiet: false,
        noResolve: false,
        statistics: [],
        tcpStream: '',
        twoPass: false,
        packetCount: '',
        outputFile: '',
        decodeAs: ''
    });

    // Reset UI
    elements.inputSourceRadios.forEach(radio => radio.checked = radio.value === 'file');
    elements.inputFile.value = 'capture.pcap';
    elements.inputInterface.value = '';
    elements.promiscuous.checked = false;
    elements.monitor.checked = false;

    elements.protoChips.forEach(chip => chip.classList.remove('active'));
    elements.srcIp.value = '';
    elements.dstIp.value = '';
    elements.port.value = '';
    elements.containsKeyword.value = '';
    elements.customFilter.value = '';
    elements.filterLogicRadios.forEach(radio => radio.checked = radio.value === 'and');

    elements.outputFormatRadios.forEach(radio => radio.checked = radio.value === 'default');
    elements.fieldCheckboxes.forEach(cb => cb.checked = false);
    elements.separator.value = ',';
    elements.includeHeader.checked = true;
    elements.verbose.checked = false;
    elements.quiet.checked = false;
    elements.noResolve.checked = false;

    elements.statOptions.forEach(cb => cb.checked = false);
    elements.tcpStream.value = '';

    elements.twoPass.checked = false;
    elements.packetCount.value = '';
    elements.outputFile.value = '';
    elements.decodeAs.value = '';

    elements.scenarioCards.forEach(card => card.classList.remove('active'));

    // Update Toggle Cards UI
    document.querySelectorAll('.toggle-option').forEach(opt => {
        opt.classList.toggle('active', opt.querySelector('input').checked);
    });

    toggleInputGroups();
    toggleFieldsOptions();
    generateCommand();
}

function loadSettings() {
    const savedPath = localStorage.getItem('tshark-path');
    if (savedPath) {
        state.tsharkPath = savedPath;
        elements.tsharkPath.value = savedPath;
    }
}

// ===== AI Assistant =====
const aiState = {
    apiBaseUrl: 'https://api.openai.com/v1',
    apiKey: '',
    model: 'gpt-4',
    isLoading: false
};

const aiElements = {};

function initAI() {
    aiElements.modal = document.getElementById('aiModal');
    aiElements.overlay = aiElements.modal.querySelector('.modal-overlay');
    aiElements.openBtn = document.getElementById('aiAssistantBtn');
    aiElements.closeBtn = document.getElementById('closeAiModal');
    aiElements.settingsBtn = document.getElementById('aiSettingsBtn');
    aiElements.settingsPanel = document.getElementById('aiSettings');
    aiElements.saveSettingsBtn = document.getElementById('saveApiSettings');
    aiElements.apiBaseUrl = document.getElementById('apiBaseUrl');
    aiElements.apiKey = document.getElementById('apiKey');
    aiElements.apiModel = document.getElementById('apiModel');
    aiElements.chatMessages = document.getElementById('chatMessages');
    aiElements.chatInput = document.getElementById('chatInput');
    aiElements.sendBtn = document.getElementById('sendMessage');
    aiElements.sendBtnText = document.getElementById('sendBtnText');
    aiElements.sendBtnLoading = document.getElementById('sendBtnLoading');

    loadAISettings();

    aiElements.openBtn.addEventListener('click', openAIModal);
    aiElements.closeBtn.addEventListener('click', closeAIModal);
    aiElements.overlay.addEventListener('click', closeAIModal);
    aiElements.settingsBtn.addEventListener('click', toggleSettings);
    aiElements.saveSettingsBtn.addEventListener('click', saveAISettings);
    aiElements.sendBtn.addEventListener('click', sendMessage);
    aiElements.chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
}

function loadAISettings() {
    const saved = localStorage.getItem('tshark-ai-settings');
    if (saved) {
        try {
            const settings = JSON.parse(saved);
            aiState.apiBaseUrl = settings.apiBaseUrl || 'https://api.openai.com/v1';
            aiState.apiKey = settings.apiKey || '';
            aiState.model = settings.model || 'gpt-4';

            aiElements.apiBaseUrl.value = aiState.apiBaseUrl;
            aiElements.apiKey.value = aiState.apiKey;
            aiElements.apiModel.value = aiState.model;
        } catch (e) {
            console.error('Failed to load AI settings:', e);
        }
    }
}

function saveAISettings() {
    aiState.apiBaseUrl = aiElements.apiBaseUrl.value.trim() || 'https://api.openai.com/v1';
    aiState.apiKey = aiElements.apiKey.value.trim();
    aiState.model = aiElements.apiModel.value.trim() || 'gpt-4';

    localStorage.setItem('tshark-ai-settings', JSON.stringify({
        apiBaseUrl: aiState.apiBaseUrl,
        apiKey: aiState.apiKey,
        model: aiState.model
    }));

    toggleSettings();
    showToast();
}

function openAIModal() {
    aiElements.modal.classList.remove('hidden');
    aiElements.chatInput.focus();
}

function closeAIModal() {
    aiElements.modal.classList.add('hidden');
}

function toggleSettings() {
    aiElements.settingsPanel.classList.toggle('hidden');
}

async function sendMessage() {
    const message = aiElements.chatInput.value.trim();
    if (!message || aiState.isLoading) return;

    if (!aiState.apiKey) {
        addMessage('assistant', '⚠️ 请先点击右上角的 ⚙️ 按钮配置 API Key。');
        toggleSettings();
        return;
    }

    addMessage('user', message);
    aiElements.chatInput.value = '';
    setLoading(true);

    try {
        const response = await callGPT(message);
        addMessage('assistant', response);
    } catch (error) {
        console.error('API Error:', error);
        addMessage('assistant', `❌ API 调用失败: ${error.message}\n\n请检查 API Key 和 Base URL 是否正确。`);
    } finally {
        setLoading(false);
    }
}

function addMessage(role, content) {
    const div = document.createElement('div');
    div.className = `chat-message ${role}`;
    const formattedContent = formatMessageContent(content);
    div.innerHTML = `<div class="message-content">${formattedContent}</div>`;
    aiElements.chatMessages.appendChild(div);
    aiElements.chatMessages.scrollTop = aiElements.chatMessages.scrollHeight;

    div.querySelectorAll('.copy-cmd-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const code = btn.parentElement.querySelector('code').textContent;
            navigator.clipboard.writeText(code);
            btn.textContent = '✓ 已复制';
            setTimeout(() => btn.textContent = '复制', 1500);
        });
    });
}

function formatMessageContent(content) {
    let formatted = content
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    formatted = formatted.replace(/```(\w*)\n?([\s\S]*?)```/g, (match, lang, code) => {
        const trimmedCode = code.trim();
        if (lang === 'bash' || lang === 'shell' || lang === '' || trimmedCode.startsWith('tshark')) {
            return `<div class="command-block"><button class="copy-cmd-btn">复制</button><code>${trimmedCode}</code></div>`;
        }
        return `<pre><code>${trimmedCode}</code></pre>`;
    });

    formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
    formatted = formatted.replace(/\n/g, '<br>');
    return formatted;
}

function setLoading(loading) {
    aiState.isLoading = loading;
    aiElements.sendBtn.disabled = loading;
    aiElements.sendBtnText.classList.toggle('hidden', loading);
    aiElements.sendBtnLoading.classList.toggle('hidden', !loading);
}

async function callGPT(userMessage) {
    const systemPrompt = `你是一个专业的网络流量分析和电子取证专家。用户会描述他们的流量分析题目或需求，你需要帮助他们生成正确的 tshark 命令。

你的回复应该：
1. 简要分析用户的需求
2. 给出一个或多个 tshark 命令，使用 \`\`\`bash 代码块格式
3. 简要解释命令的作用
4. 如果需要多步分析，按步骤给出命令

当前用户的 tshark 路径配置为: ${state.tsharkPath}
当前用户的 pcap 文件路径为: ${state.inputFile}

请用中文回复。`;

    const url = `${aiState.apiBaseUrl}/chat/completions`;

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${aiState.apiKey}`
        },
        body: JSON.stringify({
            model: aiState.model,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userMessage }
            ],
            temperature: 0.7,
            max_tokens: 2000
        })
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error?.message || `HTTP ${response.status}`);
    }

    const data = await response.json();
    return data.choices[0].message.content;
}

// ===== Knowledge Base Functions =====
let currentKnowledgeEntry = null;
let knowledgeActiveCategory = 'all';

function initKnowledgeBase() {
    if (typeof knowledgeBase === 'undefined') {
        console.warn('Knowledge base not loaded');
        return;
    }

    renderKnowledgeCategories();
    renderKnowledgeEntries();
    bindKnowledgeEvents();
}

function renderKnowledgeCategories() {
    if (!elements.knowledgeCategories) return;

    let html = `<button class="category-btn active" data-category="all">📋 全部</button>`;

    knowledgeBase.categories.forEach(cat => {
        html += `<button class="category-btn" data-category="${cat.id}">${cat.icon} ${cat.name}</button>`;
    });

    elements.knowledgeCategories.innerHTML = html;
}

function renderKnowledgeEntries(filter = '') {
    if (!elements.knowledgeList) return;

    let entries = knowledgeBase.entries;

    // 按分类过滤
    if (knowledgeActiveCategory !== 'all') {
        entries = entries.filter(e => e.category === knowledgeActiveCategory);
    }

    // 按搜索词过滤
    if (filter) {
        const lowerFilter = filter.toLowerCase();
        entries = entries.filter(e =>
            e.title.toLowerCase().includes(lowerFilter) ||
            e.description.toLowerCase().includes(lowerFilter) ||
            e.tags.some(t => t.toLowerCase().includes(lowerFilter))
        );
    }

    const getCategoryIcon = (catId) => {
        const cat = knowledgeBase.categories.find(c => c.id === catId);
        return cat ? cat.icon : '📄';
    };

    const difficultyText = { easy: '简单', medium: '中等', hard: '困难' };

    let html = '';
    entries.forEach(entry => {
        html += `
            <div class="knowledge-card" data-id="${entry.id}">
                <div class="card-header">
                    <span class="card-icon">${getCategoryIcon(entry.category)}</span>
                    <span class="card-title">${entry.title}</span>
                </div>
                <p class="card-desc">${entry.description}</p>
                <div class="card-tags">
                    <span class="difficulty ${entry.difficulty}">${difficultyText[entry.difficulty]}</span>
                    ${entry.tags.slice(0, 3).map(t => `<span class="tag">${t}</span>`).join('')}
                </div>
            </div>
        `;
    });

    if (entries.length === 0) {
        html = '<p style="color: var(--text-secondary); text-align: center; padding: 40px;">未找到匹配的知识条目</p>';
    }

    elements.knowledgeList.innerHTML = html;
}

function showKnowledgeDetail(entryId) {
    const entry = knowledgeBase.entries.find(e => e.id === entryId);
    if (!entry) return;

    currentKnowledgeEntry = entry;

    document.getElementById('detailTitle').textContent = entry.title;
    document.getElementById('detailDesc').textContent = entry.description;
    document.getElementById('detailFilter').textContent = entry.tsharkFilter || '(无特定过滤器)';

    // 渲染技巧
    const tipsHtml = entry.tips.map(tip => `<li>${tip}</li>`).join('');
    document.getElementById('detailTips').innerHTML = tipsHtml;

    // 渲染命令
    const cmdsHtml = entry.commands.map(cmd => `<div class="command-block">${cmd}</div>`).join('');
    document.getElementById('detailCommands').innerHTML = cmdsHtml;

    elements.knowledgeDetail.classList.remove('hidden');
}

function hideKnowledgeDetail() {
    elements.knowledgeDetail.classList.add('hidden');
    currentKnowledgeEntry = null;
}

function applyKnowledgeFilter() {
    if (!currentKnowledgeEntry) return;

    // 应用过滤器到自定义过滤框
    if (currentKnowledgeEntry.tsharkFilter) {
        elements.customFilter.value = currentKnowledgeEntry.tsharkFilter;
        state.customFilter = currentKnowledgeEntry.tsharkFilter;
    }

    // 如果有预设字段，则选中
    if (currentKnowledgeEntry.tsharkFields && currentKnowledgeEntry.tsharkFields.length > 0) {
        // 清除现有选择
        elements.fieldCheckboxes.forEach(cb => cb.checked = false);
        state.selectedFields = [];

        // 选中预设字段
        currentKnowledgeEntry.tsharkFields.forEach(field => {
            const checkbox = Array.from(elements.fieldCheckboxes).find(cb => cb.value === field);
            if (checkbox) {
                checkbox.checked = true;
                state.selectedFields.push(field);
            }
        });

        // 如果有字段，切换到字段输出模式
        if (state.selectedFields.length > 0) {
            const fieldsRadio = document.querySelector('input[name="outputFormat"][value="fields"]');
            if (fieldsRadio) {
                fieldsRadio.checked = true;
                state.outputFormat = 'fields';
                toggleFieldsOptions();
            }
        }
    }

    generateCommand();
    hideKnowledgeDetail();

    // 切换到过滤器Tab
    document.querySelector('[data-tab="filters"]').click();
    showToast('已应用知识库过滤器');
}

function bindKnowledgeEvents() {
    // 分类按钮
    if (elements.knowledgeCategories) {
        elements.knowledgeCategories.addEventListener('click', (e) => {
            const btn = e.target.closest('.category-btn');
            if (!btn) return;

            elements.knowledgeCategories.querySelectorAll('.category-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            knowledgeActiveCategory = btn.dataset.category;
            renderKnowledgeEntries(elements.knowledgeSearch?.value || '');
        });
    }

    // 搜索框
    if (elements.knowledgeSearch) {
        let searchTimeout;
        elements.knowledgeSearch.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                renderKnowledgeEntries(e.target.value);
            }, 200);
        });
    }

    // 知识卡片点击
    if (elements.knowledgeList) {
        elements.knowledgeList.addEventListener('click', (e) => {
            const card = e.target.closest('.knowledge-card');
            if (card) {
                showKnowledgeDetail(card.dataset.id);
            }
        });
    }

    // 关闭详情面板
    if (elements.closeDetail) {
        elements.closeDetail.addEventListener('click', hideKnowledgeDetail);
    }

    // 应用过滤器
    if (elements.applyKnowledge) {
        elements.applyKnowledge.addEventListener('click', applyKnowledgeFilter);
    }
}

// 在init后调用
setTimeout(initKnowledgeBase, 100);
