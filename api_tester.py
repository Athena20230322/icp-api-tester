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


# <editor-fold desc="Cryptographic and API Client Classes">
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


class CertificateApiClient:
    def __init__(self, base_url=""):
        self.base_url = base_url
        self.rsa_helper = RsaCryptoHelper()
        self.session = requests.Session()
        try:
            system_proxies = urllib.request.getproxies()
            self.session.proxies.update(system_proxies)
        except Exception as e:
            print(f"Could not load system proxies: {e}")
        self._server_public_key = None
        self._client_private_key = None
        self._aes_key = None
        self._aes_iv = None
        self.is_ready = False

    def _build_url(self, path):
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _check_timestamp(self, timestamp_str):
        try:
            dt = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
            if abs((datetime.now() - dt).total_seconds()) > 300:
                print(f"Warning: Timestamp difference is high for {timestamp_str}")
        except (ValueError, TypeError):
            print(f"Could not parse timestamp: {timestamp_str}")

    def _call_raw_api(self, url, data=None, headers=None):
        try:
            response = self.session.post(url, data=data, headers=headers, timeout=30, verify=True)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error calling {url}: {e}")

    def _call_certificate_api(self, action, cert_id, server_key, client_key, payload, cert_header):
        json_payload = json.dumps(payload, ensure_ascii=False)
        self.rsa_helper.import_pem_public_key(server_key)
        enc_data = self.rsa_helper.encrypt(json_payload)
        self.rsa_helper.import_pem_private_key(client_key)
        signature = self.rsa_helper.sign_data_with_sha256(enc_data)
        url = self._build_url(action)
        response = self._call_raw_api(
            url,
            data={'EncData': enc_data},
            headers={cert_header: str(cert_id), 'X-iCP-Signature': signature}
        )
        return response.text, response.headers.get('X-iCP-Signature')

    def perform_handshake(self):
        url_get_cert = self._build_url("api/member/Certificate/GetDefaultPucCert")
        resp = self._call_raw_api(url_get_cert)

        data_cert = resp.json()
        if data_cert['RtnCode'] != 1:
            raise Exception(f"GetDefaultPucCert Error: {data_cert['RtnMsg']}")
        default_cert_id, default_public_key = data_cert['DefaultPubCertID'], data_cert['DefaultPubCert']

        client_keys = self.rsa_helper.generate_pem_key()
        self._client_private_key = client_keys['private_key']
        pub_key_oneline = "".join(client_keys['public_key'].splitlines()[1:-1])
        payload_exchange = {'ClientPubCert': pub_key_oneline, 'Timestamp': datetime.now().strftime("%Y/%m/%d %H:%M:%S")}

        content_ex, sig_ex = self._call_certificate_api(
            "api/member/Certificate/ExchangePucCert", default_cert_id, default_public_key,
            self._client_private_key, payload_exchange, "X-iCP-DefaultPubCertID"
        )
        result_ex = json.loads(content_ex)
        if result_ex['RtnCode'] != 1:
            raise Exception(f"ExchangePucCert Error: {result_ex['RtnMsg']}")

        self.rsa_helper.import_pem_private_key(self._client_private_key)
        decrypted_ex = self.rsa_helper.decrypt(result_ex['EncData'])
        data_ex = json.loads(decrypted_ex)
        self._server_public_key = data_ex['ServerPubCert']

        self.rsa_helper.import_pem_public_key(self._server_public_key)
        if not self.rsa_helper.verify_sign_data_with_sha256(content_ex, sig_ex):
            raise Exception("Signature verification failed during key exchange.")

        self._check_timestamp(data_ex['Timestamp'])

        payload_aes = {'Timestamp': datetime.now().strftime("%Y/%m/%d %H:%M:%S")}
        content_aes, sig_aes = self._call_certificate_api(
            "api/member/Certificate/GenerateAES", data_ex['ServerPubCertID'],
            self._server_public_key, self._client_private_key, payload_aes, "X-iCP-ServerPubCertID"
        )
        result_aes = json.loads(content_aes)
        if result_aes['RtnCode'] != 1:
            raise Exception(f"GenerateAES Error: {result_aes['RtnMsg']}")

        self.rsa_helper.import_pem_public_key(self._server_public_key)
        if not self.rsa_helper.verify_sign_data_with_sha256(content_aes, sig_aes):
            raise Exception("Signature verification failed during AES generation.")

        self.rsa_helper.import_pem_private_key(self._client_private_key)
        decrypted_aes = self.rsa_helper.decrypt(result_aes['EncData'])
        data_aes = json.loads(decrypted_aes)
        self._check_timestamp(data_aes['Timestamp'])

        self._aes_client_cert_id = data_aes['EncKeyID']
        self._aes_key = data_aes['AES_Key']
        self._aes_iv = data_aes['AES_IV']
        self.is_ready = True

    def call_api(self, action, payload):
        if not self.is_ready:
            raise Exception("Client is not ready. Perform handshake first.")

        if 'Timestamp' not in payload:
            payload['Timestamp'] = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        json_payload = json.dumps(payload, ensure_ascii=False)

        aes_helper = AesCryptoHelper(self._aes_key, self._aes_iv)
        enc_data = aes_helper.encrypt(json_payload)

        self.rsa_helper.import_pem_private_key(self._client_private_key)
        signature = self.rsa_helper.sign_data_with_sha256(enc_data)

        url = self._build_url(action)

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

# ******** START: 修正部分 ********
# 建立一個簡單的字典來快取 API client 物件
# key 是環境名稱 (e.g., 'stage'), value 是 CertificateApiClient 物件
api_client_cache = {}
# ******** END: 修正部分 ********


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
        action = data['action']
        env = data['env']

        # 如果是重置請求，就從快取中刪除對應的 client
        if action == 'reset':
            if env in api_client_cache:
                del api_client_cache[env]
                return jsonify({'status': 'ok', 'message': f"Connection for env '{env}' has been reset."})
            return jsonify({'status': 'ok', 'message': f"No active connection found for env '{env}'."})

        # --- 以下是正常的 query 流程 ---
        host, target_url, payload = data['host'], data['url'], data['payload']

        # 檢查快取中是否已有 client
        client = api_client_cache.get(env)

        if not client:
            print(f"No cached client for env '{env}'. Creating new client and performing handshake...")
            env_hosts = load_json_file('EnvHost.json')
            base_url = env_hosts.get(env, {}).get(host)
            if not base_url:
                return jsonify({'error': f"Host '{host}' not found for env '{env}'"}), 400

            client = CertificateApiClient(base_url)
            client.perform_handshake()
            api_client_cache[env] = client  # 將新建立的 client 存入快取
        else:
            print(f"Using cached client for env '{env}'.")

        result = client.call_api(target_url, payload)

        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("Starting Flask server for ICP API Mock Tool...")
    print("Open http://127.0.0.1:50061 in your web browser.")
    print("Make sure EnvHost.json and MockApi.json are in a 'data' sub-folder.")
    # ... (前面的 print 敘述)
    app.run(host='0.0.0.0', port=50061, debug=True)
# </editor-fold>