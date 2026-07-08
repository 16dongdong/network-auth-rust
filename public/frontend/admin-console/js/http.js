(function (app) {
    'use strict';

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const cryptoKeyCache = {
        sessionKey: '',
        aesKeyPromise: null,
        hmacKeyPromise: null
    };

    async function createSession() {
        const response = await fetch(app.state.sessionUrl, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        return parsePlainResponse(response);
    }

    async function admin(route, payload) {
        assertSession();
        if (app.state.demoMode) {
            return plainDemoAdmin(route, payload || {});
        }
        const nonce = randomToken(24);
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const sessionCrypto = currentSessionCrypto();
        const body = JSON.stringify(await encryptPayload(payload || {}, sessionCrypto, requestAad(route, timestamp, nonce)));
        const signatureRequest = {route, timestamp, nonce, body, sessionCrypto};
        const response = await fetch(routeUrl(route), {
            method: 'POST',
            headers: await signedHeaders(signatureRequest),
            body
        });
        return parseEncryptedResponse(response, route, nonce, sessionCrypto);
    }

    async function adminUpload(route, formData) {
        assertSession();
        if (app.state.demoMode) {
            throw new Error('演示环境禁止上传文件');
        }
        const response = await fetch(routeUrl(route), {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'X-Admin-Session': app.state.sessionToken
            },
            body: formData
        });
        return parsePlainResponse(response);
    }

    async function plainDemoAdmin(route, payload) {
        const response = await fetch(routeUrl(route), {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Demo-Admin': '1',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(payload)
        });
        return parsePlainResponse(response);
    }

    function routeUrl(route) {
        return `${app.state.apiUrl}?route=${encodeURIComponent(route)}`;
    }

    function assertSession() {
        if (!app.state.sessionToken || !app.state.sessionKey) {
            throw new Error('请先登录后台管理端');
        }
    }

    async function signedHeaders(signatureRequest) {
        const signatureText = await canonical(signatureRequest);
        return {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Admin-Session': app.state.sessionToken,
            'X-Timestamp': signatureRequest.timestamp,
            'X-Nonce': signatureRequest.nonce,
            'X-Signature': await hmacHex(signatureRequest.sessionCrypto, signatureText)
        };
    }

    function currentSessionCrypto() {
        const keyText = app.state.sessionKey;
        return {keyText, rawKey: base64UrlDecode(keyText)};
    }

    async function encryptPayload(payload, sessionCrypto, aad) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await aesKey(sessionCrypto);
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: encoder.encode(aad), tagLength: 128}, key, encoder.encode(JSON.stringify(payload))));
        return {
            iv: base64UrlEncode(iv),
            ciphertext: base64UrlEncode(encrypted.slice(0, -16)),
            tag: base64UrlEncode(encrypted.slice(-16))
        };
    }

    async function decryptPayload(envelope, sessionCrypto, aad) {
        const key = await aesKey(sessionCrypto);
        const combined = concatBytes(base64UrlDecode(envelope.ciphertext), base64UrlDecode(envelope.tag));
        const decrypted = await crypto.subtle.decrypt({name: 'AES-GCM', iv: base64UrlDecode(envelope.iv), additionalData: encoder.encode(aad), tagLength: 128}, key, combined);
        return JSON.parse(decoder.decode(decrypted));
    }

    async function parsePlainResponse(response) {
        const result = await readJson(response);
        if (!response.ok || result.code !== 0) {
            throw new Error(result.message || result.error || '请求失败');
        }
        return result.data || {};
    }

    async function parseEncryptedResponse(response, route, nonce, sessionCrypto) {
        const result = await readJson(response);
        if (!response.ok || result.code !== 0) {
            throw new Error(result.message || result.error || '请求失败');
        }
        if (!result.data || result.data.encrypted !== true) {
            throw new Error('接口响应未加密');
        }
        return decryptPayload(result.data.payload, sessionCrypto, responseAad(route, nonce));
    }

    async function readJson(response) {
        try {
            return await response.json();
        } catch {
            throw new Error('接口返回不是有效 JSON');
        }
    }

    async function aesKey(sessionCrypto) {
        resetCryptoKeyCache(sessionCrypto.keyText);
        cryptoKeyCache.aesKeyPromise ||= crypto.subtle.importKey('raw', sessionCrypto.rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
        return cryptoKeyCache.aesKeyPromise;
    }

    async function hmacHex(sessionCrypto, message) {
        const key = await hmacKey(sessionCrypto);
        return hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(message))));
    }

    async function hmacKey(sessionCrypto) {
        resetCryptoKeyCache(sessionCrypto.keyText);
        cryptoKeyCache.hmacKeyPromise ||= crypto.subtle.importKey('raw', sessionCrypto.rawKey, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
        return cryptoKeyCache.hmacKeyPromise;
    }

    function resetCryptoKeyCache(sessionKeyText) {
        if (cryptoKeyCache.sessionKey === sessionKeyText) {
            return;
        }
        cryptoKeyCache.sessionKey = sessionKeyText;
        cryptoKeyCache.aesKeyPromise = null;
        cryptoKeyCache.hmacKeyPromise = null;
    }

    async function sha256Hex(value) {
        return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
    }

    async function canonical(signatureRequest) {
        return `POST\n${signatureRequest.route}\n${signatureRequest.timestamp}\n${signatureRequest.nonce}\n${await sha256Hex(signatureRequest.body)}`;
    }

    function requestAad(route, timestamp, nonce) {
        return `POST\n${route}\n${timestamp}\n${nonce}`;
    }

    function responseAad(route, nonce) {
        return `RESPONSE\n${route}\n${nonce}`;
    }

    function randomToken(bytes) {
        return base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
    }

    function base64UrlEncode(bytes) {
        let binary = '';
        bytes.forEach((value) => {
            binary += String.fromCharCode(value);
        });
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function base64UrlDecode(value) {
        const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
        return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
    }

    function concatBytes(left, right) {
        const merged = new Uint8Array(left.length + right.length);
        merged.set(left);
        merged.set(right, left.length);
        return merged;
    }

    function hex(bytes) {
        return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
    }

    app.http = {admin, adminUpload, createSession};
})(window.NetworkAuthAdmin);
