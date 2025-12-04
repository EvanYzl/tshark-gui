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

// ===== Scenario Presets =====
const scenarios = {
    protocol: {
        name: '协议分布',
        config: {
            quiet: true,
            statistics: ['io,phs']
        }
    },
    ipconv: {
        name: 'IP通信对',
        config: {
            quiet: true,
            statistics: ['conv,ip']
        }
    },
    http: {
        name: 'HTTP请求',
        config: {
            selectedProtocols: ['http.request'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.request.uri', 'http.request.method']
        }
    },
    dns: {
        name: 'DNS查询',
        config: {
            selectedProtocols: ['dns.qry.name'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'dns.qry.name', 'dns.a']
        }
    },
    credentials: {
        name: '提取凭据',
        config: {
            customFilter: 'ftp.request.command == "USER" || ftp.request.command == "PASS" || http.authorization || http.cookie contains "session"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'ip.dst', 'ftp.request.command', 'ftp.request.arg']
        }
    },
    useragent: {
        name: 'User-Agent',
        config: {
            selectedProtocols: ['http.user_agent'],
            outputFormat: 'fields',
            selectedFields: ['ip.src', 'http.host', 'http.user_agent']
        }
    },
    cookies: {
        name: 'Cookies',
        config: {
            selectedProtocols: ['http.cookie'],
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.cookie']
        }
    },
    post: {
        name: 'POST数据',
        config: {
            customFilter: 'http.request.method == "POST"',
            outputFormat: 'fields',
            selectedFields: ['frame.number', 'ip.src', 'http.host', 'http.request.uri', 'http.file_data']
        }
    },
    tcpstream: {
        name: 'TCP流追踪',
        config: {
            quiet: true,
            tcpStream: '0'
        }
    },
    suspicious: {
        name: '可疑流量',
        config: {
            customFilter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
            quiet: true,
            statistics: ['conv,ip']
        }
    },
    timeline: {
        name: '时间线',
        config: {
            outputFormat: 'fields',
            selectedFields: ['frame.time', 'ip.src', 'ip.dst', 'frame.protocols', 'frame.len']
        }
    },
    expert: {
        name: '专家分析',
        config: {
            quiet: true,
            statistics: ['expert']
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
