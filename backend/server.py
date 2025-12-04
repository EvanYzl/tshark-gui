#!/usr/bin/env python3
"""
TShark GUI - 本地执行后端服务
支持在浏览器中运行tshark命令和解密工具
"""

import os
import sys
import subprocess
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='..', static_url_path='')
CORS(app)

# 获取项目根目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(BASE_DIR, 'tools')

@app.route('/')
def index():
    """服务前端页面"""
    return send_from_directory(app.static_folder, 'modern.html')

@app.route('/api/run', methods=['POST'])
def run_command():
    """
    执行tshark命令
    POST /api/run
    Body: { "command": "tshark -r file.pcap ..." }
    """
    try:
        data = request.get_json()
        command = data.get('command', '')
        
        if not command:
            return jsonify({'success': False, 'error': '命令不能为空'})
        
        # 安全检查：只允许tshark相关命令
        if not (command.strip().startswith('tshark') or 
                command.strip().startswith('"') and 'tshark' in command):
            return jsonify({'success': False, 'error': '只允许执行tshark命令'})
        
        # 执行命令
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,  # 2分钟超时
            cwd=BASE_DIR
        )
        
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None,
            'returncode': result.returncode
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': '命令执行超时 (120秒)'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/decrypt', methods=['POST'])
def decrypt_traffic():
    """
    执行Webshell解密工具
    POST /api/decrypt
    Body: {
        "tool": "behinder" | "godzilla",
        "pcapFile": "path/to/file.pcap",
        "options": { ... }
    }
    """
    try:
        data = request.get_json()
        tool = data.get('tool', '')
        pcap_file = data.get('pcapFile', '')
        options = data.get('options', {})
        
        if tool == 'behinder':
            # 冰蝎解密
            script = os.path.join(TOOLS_DIR, 'behinder-decryptor', 'Behinder-Decrypt.py')
            url = options.get('url', '/shell.php')
            shell_type = options.get('type', 'php')
            key = options.get('key', 'e45e329feb5d925b')
            
            cmd = f'python3 "{script}" -f "{pcap_file}" -u "{url}" -t {shell_type} -k {key}'
            
        elif tool == 'godzilla':
            # 哥斯拉解密
            script = os.path.join(TOOLS_DIR, 'WSTDecryptor', 'WSTDecryptor.py')
            server_ip = options.get('serverIp', '')
            key = options.get('key', '')
            
            if server_ip and key:
                cmd = f'python3 "{script}" godzilla -p "{pcap_file}" -i {server_ip} -k {key}'
            else:
                cmd = f'python3 "{script}" findshell -p "{pcap_file}"'
        else:
            return jsonify({'success': False, 'error': f'不支持的工具: {tool}'})
        
        # 执行解密命令
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=180,  # 3分钟超时
            cwd=BASE_DIR
        )
        
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None,
            'command': cmd,
            'returncode': result.returncode
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': '解密执行超时 (180秒)'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/status', methods=['GET'])
def status():
    """检查服务状态和工具可用性"""
    status_info = {
        'server': 'running',
        'tshark': False,
        'python': True,
        'tools': {
            'behinder': os.path.exists(os.path.join(TOOLS_DIR, 'behinder-decryptor', 'Behinder-Decrypt.py')),
            'godzilla': os.path.exists(os.path.join(TOOLS_DIR, 'WSTDecryptor', 'WSTDecryptor.py'))
        }
    }
    
    # 检查tshark是否可用
    try:
        result = subprocess.run(['tshark', '--version'], capture_output=True, timeout=5)
        status_info['tshark'] = result.returncode == 0
    except:
        pass
    
    return jsonify(status_info)

if __name__ == '__main__':
    print("=" * 50)
    print("  TShark GUI 本地执行服务")
    print("=" * 50)
    print(f"  前端页面: http://localhost:8765/")
    print(f"  API地址:  http://localhost:8765/api/")
    print("=" * 50)
    app.run(host='0.0.0.0', port=8765, debug=True)
