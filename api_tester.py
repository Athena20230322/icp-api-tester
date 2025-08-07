import json
import base64
import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify

import urllib.request
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


# <editor-fold desc="Cryptographic Helper Classes">
class RsaCryptoHelper:
    def __init__(self):
        self._key = None

    def generate_pem_key(self):
        key = RSA.generate(2048)
        private_key_pem = key.export_key(format='PEM', pkcs=8).decode('utf-8')
        public_key_pem = key.publickey().export_key(format='PEM').decode('utf-8')
        return {'private_key': private_key_pem, 'public_key': public_key_pem}

    def import_pem_public_key(self, pem_key):
        if not pem_key.strip().startswith('-----BEGIN'):
            pem_key = f"-----BEGIN PUBLIC KEY-----\n{pem_key}\n-----END PUBLIC KEY-----"
        self._key = RSA.import_key(pem_key)

    def import_pem_private_key(self, pem_key):
        self._key = RSA.import_key(pem_key)

    def encrypt(self, data):
        key_size_bytes = self._key.size_in_bytes()
        max_chunk_size = key_size_bytes - 11
        data_bytes = data.encode('utf-8')
        encrypted_chunks = []
        for i in range(0, len(data_bytes), max_chunk_size):
            chunk = data_bytes[i:i + max_chunk_size]
            cipher_rsa = PKCS1_v1_5.new(self._key)
            encrypted_chunks.append(cipher_rsa.encrypt(chunk))
        return base64.b64encode(b''.join(encrypted_chunks)).decode('utf-8')

    def decrypt(self, enc_data):
        try:
            encrypted_bytes = base64.b64decode(enc_data)
            key_size_bytes = self._key.size_in_bytes()
            decrypted_chunks = []
            for i in range(0, len(encrypted_bytes), key_size_bytes):
                chunk = encrypted_bytes[i:i + key_size_bytes]
                cipher_rsa = PKCS1_v1_5.new(self._key)
                decrypted_chunks.append(cipher_rsa.decrypt(chunk, 'error_sentinel'))
            if b'error_sentinel' in decrypted_chunks:
                raise ValueError("Decryption failed for at least one block.")
            return b''.join(decrypted_chunks).decode('utf-8')
        except Exception:
            raise ValueError("Decryption failed. Check RSA key or data.")

    def sign_data_with_sha256(self, data):
        h = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(self._key).sign(h)
        return base64.b64encode(signature).decode('utf-8')

    def verify_sign_data_with_sha256(self, data, signature):
        h = SHA256.new(data.encode('utf-8'))
        signature_bytes = base64.b64decode(signature)
        try:
            pkcs1_15.new(self._key).verify(h, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False


class AesCryptoHelper:
    def __init__(self, key=None, iv=None):
        self.key = key.encode('utf-8') if key else None
        self.iv = iv.encode('utf-8') if iv else None

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size, style='pkcs7')
        encrypted_bytes = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    def decrypt(self, enc_data):
        encrypted_bytes = base64.b64decode(enc_data)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
        unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size, style='pkcs7')
        return unpadded_bytes.decode('utf-8')


# </editor-fold>

# <editor-fold desc="API Environment and Client Logic">
# ******** START: 架構修正 ********
# 建立一個新的 ApiEnvironment 類別來統一管理狀態
class ApiEnvironment:
    def __init__(self, env_name, env_hosts):
        self.env_name = env_name
        self.env_hosts = env_hosts
        self.session = requests.Session()
        try:
            self.session.proxies.update(urllib.request.getproxies())
        except Exception as e:
            print(f"Could not load system proxies: {e}")

        self.rsa_helper = RsaCryptoHelper()
        self._server_public_key = None
        self._client_private_key = None
        self._aes_key = None
        self._aes_iv = None
        self._aes_client_cert_id = None
        self.is_ready = False

    def _build_url(self, path, base_url):
        return f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    def _call_raw_api(self, url, data=None, headers=None):
        try:
            # 使用 verify=False 是為了繞過可能的公司 SSL 憑證攔截，若環境單純可改回 True
            response = self.session.post(url, data=data, headers=headers, timeout=30, verify=False)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error calling {url}: {e}")

    def perform_handshake(self):
        if self.is_ready:
            return

        print(f"Performing handshake for environment '{self.env_name}'...")
        member_base_url = self.env_hosts.get("member")
        if not member_base_url:
            raise ValueError(f"'member' host not defined for env '{self.env_name}'")

        # 1. Get Default Public Certificate
        url_get_cert = self._build_url("api/member/Certificate/GetDefaultPucCert", member_base_url)
        resp = self._call_raw_api(url_get_cert)
        data_cert = resp.json()
        if data_cert['RtnCode'] != 1:
            raise Exception(f"GetDefaultPucCert Error: {data_cert['RtnMsg']}")
        default_cert_id, default_public_key = data_cert['DefaultPubCertID'], data_cert['DefaultPubCert']

        # 2. Exchange Public Keys
        client_keys = self.rsa_helper.generate_pem_key()
        self._client_private_key = client_keys['private_key']
        pub_key_oneline = "".join(client_keys['public_key'].splitlines()[1:-1])
        payload_exchange = {'ClientPubCert': pub_key_oneline, 'Timestamp': datetime.now().strftime("%Y/%m/%d %H:%M:%S")}

        json_payload_ex = json.dumps(payload_exchange, ensure_ascii=False)
        self.rsa_helper.import_pem_public_key(default_public_key)
        enc_data_ex = self.rsa_helper.encrypt(json_payload_ex)
        self.rsa_helper.import_pem_private_key(self._client_private_key)
        sig_ex = self.rsa_helper.sign_data_with_sha256(enc_data_ex)

        url_exchange = self._build_url("api/member/Certificate/ExchangePucCert", member_base_url)
        resp_ex = self._call_raw_api(url_exchange, data={'EncData': enc_data_ex},
                                     headers={"X-iCP-DefaultPubCertID": str(default_cert_id),
                                              'X-iCP-Signature': sig_ex})
        content_ex = resp_ex.text

        result_ex = json.loads(content_ex)
        if result_ex['RtnCode'] != 1:
            raise Exception(f"ExchangePucCert Error: {result_ex['RtnMsg']}")

        self.rsa_helper.import_pem_private_key(self._client_private_key)
        decrypted_ex = self.rsa_helper.decrypt(result_ex['EncData'])
        data_ex = json.loads(decrypted_ex)
        self._server_public_key = data_ex['ServerPubCert']

        self.rsa_helper.import_pem_public_key(self._server_public_key)
        if not self.rsa_helper.verify_sign_data_with_sha256(content_ex, resp_ex.headers.get('X-iCP-Signature')):
            raise Exception("Signature verification failed during key exchange.")

        # 3. Generate AES Key
        payload_aes = {'Timestamp': datetime.now().strftime("%Y/%m/%d %H:%M:%S")}
        json_payload_aes = json.dumps(payload_aes, ensure_ascii=False)
        self.rsa_helper.import_pem_public_key(self._server_public_key)
        enc_data_aes = self.rsa_helper.encrypt(json_payload_aes)
        self.rsa_helper.import_pem_private_key(self._client_private_key)
        sig_aes = self.rsa_helper.sign_data_with_sha256(enc_data_aes)

        url_aes = self._build_url("api/member/Certificate/GenerateAES", member_base_url)
        resp_aes = self._call_raw_api(url_aes, data={'EncData': enc_data_aes},
                                      headers={"X-iCP-ServerPubCertID": str(data_ex['ServerPubCertID']),
                                               'X-iCP-Signature': sig_aes})
        content_aes = resp_aes.text

        result_aes = json.loads(content_aes)
        if result_aes['RtnCode'] != 1:
            raise Exception(f"GenerateAES Error: {result_aes['RtnMsg']}")

        self.rsa_helper.import_pem_public_key(self._server_public_key)
        if not self.rsa_helper.verify_sign_data_with_sha256(content_aes, resp_aes.headers.get('X-iCP-Signature')):
            raise Exception("Signature verification failed during AES generation.")

        self.rsa_helper.import_pem_private_key(self._client_private_key)
        decrypted_aes = self.rsa_helper.decrypt(result_aes['EncData'])
        data_aes = json.loads(decrypted_aes)

        self._aes_client_cert_id = data_aes['EncKeyID']
        self._aes_key = data_aes['AES_Key']
        self._aes_iv = data_aes['AES_IV']
        self.is_ready = True
        print(f"Handshake for environment '{self.env_name}' completed successfully.")

    def call_api(self, host_type, action, payload):
        if not self.is_ready:
            self.perform_handshake()

        target_base_url = self.env_hosts.get(host_type)
        if not target_base_url:
            raise ValueError(f"Host type '{host_type}' not found in env '{self.env_name}'")

        if 'Timestamp' not in payload:
            payload['Timestamp'] = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        json_payload = json.dumps(payload, ensure_ascii=False)

        aes_helper = AesCryptoHelper(self._aes_key, self._aes_iv)
        enc_data = aes_helper.encrypt(json_payload)

        self.rsa_helper.import_pem_private_key(self._client_private_key)
        signature = self.rsa_helper.sign_data_with_sha256(enc_data)

        url = self._build_url(action, target_base_url)

        resp = self._call_raw_api(
            url,
            data={'EncData': enc_data},
            headers={'X-iCP-EncKeyID': str(self._aes_client_cert_id), 'X-iCP-Signature': signature}
        )

        resp_content = resp.text
        resp_sig = resp.headers.get('X-iCP-Signature')

        if resp_sig:
            self.rsa_helper.import_pem_public_key(self._server_public_key)
            if not self.rsa_helper.verify_sign_data_with_sha256(resp_content, resp_sig):
                raise Exception("API response signature verification failed.")
        else:
            print(f"Warning: No 'X-iCP-Signature' header in response for API {action}. Skipping verification.")

        if not resp_content.strip():
            return {"RtnCode": 1, "RtnMsg": "Success (No Content)"}

        resp_json = json.loads(resp_content)

        if resp_json.get('EncData'):
            decrypted_content = aes_helper.decrypt(resp_json['EncData'])
            final_response = resp_json.copy()
            final_response['EncData'] = json.loads(decrypted_content)
            return final_response
        else:
            return resp_json


# </editor-fold>

# <editor-fold desc="Flask Web Application">
app = Flask(__name__)

# 全域的環境快取
# key 是環境名稱 (e.g., 'stage'), value 是 ApiEnvironment 物件
api_env_cache = {}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Python ICP API Mock Tool</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f4f4f9; color: #333; }
        .container { display: flex; height: 100vh; }
        .sidebar { width: 350px; background-color: #fff; border-right: 1px solid #ddd; overflow-y: auto; padding: 10px; }
        .main-content { flex-grow: 1; padding: 20px; display: flex; flex-direction: column; overflow-y: auto; }
        h2 { color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 5px; margin-top: 0; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 8px 12px; cursor: pointer; border-radius: 4px; margin-bottom: 4px; }
        li:hover { background-color: #e9ecef; }
        li.active { background-color: #007bff; color: white; }
        .api-group h3 { margin: 15px 0 5px 5px; color: #555; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], select, textarea {
            width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;
            font-family: Consolas, 'Courier New', monospace; font-size: 14px;
        }
        textarea { height: 200px; resize: vertical; }
        .button-group { display: flex; align-items: center; }
        .button-group button { margin-right: 10px; }
        button {
            background-color: #28a745; color: white; padding: 10px 15px; border: none;
            border-radius: 4px; cursor: pointer; font-size: 16px;
        }
        button:hover { background-color: #218838; }
        button:disabled { background-color: #aaa; cursor: not-allowed; }
        #reset-btn { background-color: #dc3545; }
        #reset-btn:hover { background-color: #c82333; }
        .response-area { margin-top: 20px; flex-grow: 1; display: flex; flex-direction: column; }
        .response-area textarea { flex-grow: 1; background-color: #e9ecef; }
        .spinner {
            border: 4px solid #f3f3f3; border-top: 4px solid #3498db;
            border-radius: 50%; width: 20px; height: 20px;
            animation: spin 1s linear infinite; display: none; margin-left: 10px;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <h2>API List</h2>
            {% for category in api_data %}
                <div class="api-group">
                    <h3>{{ category.category }}</h3>
                    <ul id="api-list-{{ loop.index }}">
                        {% for api in category.list %}
                            <li data-url="{{ api.url }}" 
                                data-host="{{ api.host }}" 
                                data-json='{{ api.json | tojson }}'>
                                {{ api.name }} <br> 
                                <small style="color: #888;">{{ api.url }}</small>
                            </li>
                        {% endfor %}
                    </ul>
                </div>
            {% endfor %}
        </div>
        <div class="main-content">
            <div class="request-area">
                <h2>Request</h2>
                <div class="form-group">
                    <label for="env-select">STAGE</label>
                    <select id="env-select">
                        {% for env in env_data %}
                            <option value="{{ env }}" {% if env == 'stage' %}selected{% endif %}>{{ env }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label for="api-url">API URL</label>
                    <input type="text" id="api-url" readonly>
                    <input type="hidden" id="api-host">
                </div>
                <div class="form-group">
                    <label for="request-body">Request JSON</label>
                    <textarea id="request-body"></textarea>
                </div>
                <div class="button-group">
                    <button id="query-btn">Query</button>
                    <button id="reset-btn">Reset Connection</button>
                    <div id="spinner" class="spinner"></div>
                </div>
            </div>
            <div class="response-area">
                <h2>Response</h2>
                <textarea id="response-body" readonly></textarea>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const apiUrlInput = document.getElementById('api-url');
            const apiHostInput = document.getElementById('api-host');
            const requestBodyTextarea = document.getElementById('request-body');
            const responseBodyTextarea = document.getElementById('response-body');
            const queryBtn = document.getElementById('query-btn');
            const resetBtn = document.getElementById('reset-btn');
            const envSelect = document.getElementById('env-select');
            const spinner = document.getElementById('spinner');
            let activeLi = null;

            document.querySelectorAll('.sidebar li').forEach(item => {
                item.addEventListener('click', function () {
                    if(activeLi) activeLi.classList.remove('active');
                    this.classList.add('active');
                    activeLi = this;
                    apiUrlInput.value = this.dataset.url;
                    apiHostInput.value = this.dataset.host;
                    try {
                        requestBodyTextarea.value = JSON.stringify(JSON.parse(this.dataset.json), null, 4);
                    } catch (e) {
                        requestBodyTextarea.value = "Invalid JSON in source file.";
                    }
                });
            });

            async function sendRequest(action) {
                const env = envSelect.value;
                const url = apiUrlInput.value;
                const host = apiHostInput.value;
                const rawPayload = requestBodyTextarea.value;

                if (action === 'query' && !url) {
                    alert('Please select an API from the list.');
                    return;
                }

                let payload = {};
                if (action === 'query') {
                    try {
                        payload = JSON.parse(rawPayload);
                    } catch (e) {
                        responseBodyTextarea.value = `Invalid JSON in Request Body:\\n${e}`;
                        return;
                    }
                }

                queryBtn.disabled = true;
                resetBtn.disabled = true;
                spinner.style.display = 'inline-block';
                responseBodyTextarea.value = 'Sending request...';

                try {
                    const response = await fetch('/proxy_api', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action, env, host, url, payload })
                    });
                    const result = await response.json();
                    responseBodyTextarea.value = JSON.stringify(result, null, 4);
                } catch (error) {
                    responseBodyTextarea.value = `Error: ${error.message}`;
                } finally {
                    queryBtn.disabled = false;
                    resetBtn.disabled = false;
                    spinner.style.display = 'none';
                }
            }

            queryBtn.addEventListener('click', () => sendRequest('query'));
            resetBtn.addEventListener('click', () => sendRequest('reset'));
        });
    </script>
</body>
</html>
"""


def load_json_file(filename):
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    filepath = os.path.join(data_dir, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Required file not found: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"Error reading or parsing {filename}: {e}")


@app.route('/')
def index():
    try:
        api_data = load_json_file('MockApi.json')
        env_data = load_json_file('EnvHost.json')
        return render_template_string(HTML_TEMPLATE, api_data=api_data, env_data=env_data)
    except Exception as e:
        return f"<h1>Error loading application data</h1><p>{e}</p>", 500


@app.route('/proxy_api', methods=['POST'])
def proxy_api():
    try:
        data = request.get_json()
        action_type = data['action']
        env = data['env']
        host = data.get('host')

        if action_type == 'reset':
            if env in api_env_cache:
                del api_env_cache[env]
                msg = f"Connection cache for env '{env}' has been reset."
                print(msg)
                return jsonify({'status': 'ok', 'message': msg})
            return jsonify({'status': 'ok', 'message': f"No active connection for env '{env}'."})

        target_url, payload = data['url'], data['payload']

        # ******** START: 修正部分 2 ********
        # 取得或建立當前環境的 ApiEnvironment 物件
        if env not in api_env_cache:
            print(f"No cached environment for '{env}'. Creating new environment object...")
            env_hosts = load_json_file('EnvHost.json').get(env)
            if not env_hosts:
                return jsonify({'error': f"Environment '{env}' not found in EnvHost.json"}), 400

            # 建立一個新的環境物件，它會管理自己的 session 和加密狀態
            api_env_cache[env] = ApiEnvironment(env_name=env, env_hosts=env_hosts)

        # 從快取中取得這個環境的統一管理器
        environment_client = api_env_cache.get(env)

        # 確保加密握手只在需要時執行一次
        if not environment_client.is_ready:
            environment_client.perform_handshake()

        print(f"Using established connection for env '{env}' to call API on host '{host}'.")
        # 使用這個已建立好狀態的環境物件來呼叫 API
        result = environment_client.call_api(host_type=host, action=target_url, payload=payload)
        # ******** END: 修正部分 2 ********

        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Zeabur 會透過環境變數提供 PORT，在本機執行時則預設為 50061
    port = int(os.environ.get('PORT', 50061))

    # 在生產環境中應關閉偵錯模式 (debug=False)
    # 在 Zeabur 上將由 Gunicorn 啟動，以下程式碼主要用於本機測試
    print("Starting Flask server for ICP API Mock Tool...")
    print(f"Open http://127.0.0.1:{port} in your web browser.")
    print("Make sure EnvHost.json and MockApi.json are in a 'data' sub-folder.")
    app.run(host='0.0.0.0', port=port, debug=False)
# </editor-fold>