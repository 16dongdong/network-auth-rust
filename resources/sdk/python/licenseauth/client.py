import http.client
import json
import os
import platform
import ssl
import threading
import time
import urllib.parse
from typing import Any

from .config import Config
from .crypto import (
    aesGcmDecrypt,
    aesGcmEncrypt,
    algorithmConfig,
    base64UrlEncode,
    rsaEncrypt,
    sha256Hex,
)
from .identity import DeviceIdentity, generateDeviceId, loadOrCreateDeviceIdentity


PROOF_MODE_LOCAL_KEY = "local_key_v1"
PROOF_MODE_EPHEMERAL_TICKET = "ephemeral_ticket_v1"
SECURITY_REQUESTED_ACTIONS = {"record_only", "kick_session", "disable_device", "disable_card"}
SECURITY_EVIDENCE_FIELDS = {
    "detector",
    "matched_rule",
    "module_hash",
    "symbol_hash",
    "process_hashes",
    "debug_port_open",
    "hook_count",
    "attestation_verdict",
}
SECURITY_ATTESTATION_FIELDS = {
    "provider",
    "nonce_hash",
    "challenge_hash",
    "verdict",
    "key_id",
    "certificate_hash",
    "error_code",
}
noticeCacheLock = threading.Lock()
noticeCacheValues: dict[str, tuple[float, dict]] = {}


class AuthError(Exception):
    def __init__(self, message: str, code: str = "", httpStatus: int = 0):
        super().__init__(message)
        self.code = code.strip()
        self.httpStatus = int(httpStatus)


class Client:
    def __init__(self, config: Config | None = None):
        self.configValue = config or Config()
        self.identity = None
        self.sessionToken = ""
        self.sessionTicketValue = ""
        self.sessionProofMode = ""
        self.sessionInstallId = ""
        self.sessionCounter = 0
        self.loginCardKey = ""
        self.loginInstallId = ""
        self.loginDeviceName = ""
        self.transport = HttpTransport(self.configValue)

    def login(self, cardKey: str, deviceId: str = "", deviceName: str = "") -> dict:
        installId = deviceId.strip()
        useEphemeralTicket = self.configValue.forceEphemeralTicket
        identity = None
        if not useEphemeralTicket:
            try:
                identity = self.ensureIdentity(installId)
            except Exception:
                if not self.configValue.allowEphemeralTicket:
                    raise
                useEphemeralTicket = True
        if useEphemeralTicket:
            installId = installId or generateDeviceId(self.configValue.appCode)
        else:
            installId = identity.installId
        name = resolvedDeviceName(deviceName)
        response = self.ephemeralLoginWithRetry(cardKey, installId, name) if useEphemeralTicket else self.localKeyLogin(cardKey, installId, name, identity)
        self.captureLoginContext(cardKey, installId, name)
        self.captureSession(response, installId)
        return response

    def renewSession(self) -> dict:
        if not self.canRenewSession():
            raise AuthError("login context is not initialized")
        return self.login(self.loginCardKey, self.loginInstallId, self.loginDeviceName)

    def loginChallenge(self, installId: str, deviceName: str, identity: DeviceIdentity | None, useEphemeralTicket: bool) -> dict:
        proofMode = PROOF_MODE_EPHEMERAL_TICKET if useEphemeralTicket else PROOF_MODE_LOCAL_KEY
        payload = {
            "install_id": installId,
            "device_name": deviceName,
            "device_key_mode": proofMode,
        }
        if not useEphemeralTicket:
            payload["device_public_key"] = identity.publicKeyPem
        return self.plainPost("/login/challenge", payload)

    def localKeyLogin(self, cardKey: str, installId: str, deviceName: str, identity: DeviceIdentity) -> dict:
        challenge = self.loginChallenge(installId, deviceName, identity, False)
        payload = loginPayload(cardKey, installId, deviceName, identity, challenge, self.configValue.appCode, self.configValue.appVersion, False)
        return self.post("/login", payload)

    def ephemeralLoginWithRetry(self, cardKey: str, installId: str, deviceName: str) -> dict:
        retries = max(0, int(self.configValue.loginNetworkRetries))
        delaySeconds = max(0.0, float(self.configValue.loginRetryDelaySeconds))
        for attempt in range(retries + 1):
            try:
                payload = loginPayload(cardKey, installId, deviceName, None, None, self.configValue.appCode, self.configValue.appVersion, True)
                return self.plainPost("/login", payload)
            except AuthError as error:
                if not retryableLoginError(error) or attempt >= retries:
                    raise
                time.sleep(delaySeconds * (attempt + 1))
        raise AuthError("login retry failed", "NETWORK_ERROR")

    def setLoginContext(self, cardKey: str, deviceId: str = "", deviceName: str = "") -> None:
        card = cardKey.strip()
        if not card:
            raise AuthError("card key is required")
        installId = deviceId.strip()
        if self.configValue.forceEphemeralTicket:
            installId = installId or generateDeviceId(self.configValue.appCode)
        else:
            identity = self.ensureIdentity(installId)
            installId = identity.installId
        self.loginCardKey = card
        self.loginInstallId = installId
        self.loginDeviceName = resolvedDeviceName(deviceName)

    def unbind(self, cardKey: str, deviceId: str = "") -> dict:
        identity = self.ensureIdentity(deviceId)
        timestamp = int(time.time())
        payload = {
            "card_key": requireCardKey(cardKey),
            "install_id": identity.installId,
            "timestamp": timestamp,
        }
        payload["signature"] = identity.sign(unbindCanonical(identity.installId, timestamp, cardHash(self.configValue.appCode, payload["card_key"])))
        response = self.post("/unbind", payload)
        if identity.installId == self.sessionInstallId:
            self.clearSession()
        return response

    def notice(self) -> dict:
        return cachedNotice(self.configValue, lambda: self.plainPost("/notice", {}))

    def config(self) -> dict:
        return self.sessionPost("/config", {})

    def heartbeat(self) -> dict:
        return self.sessionPost("/heartbeat", {})

    def variable(self, name: str) -> dict:
        variableName = name.strip()
        if not variableName:
            raise AuthError("variable name is required")
        return self.sessionPost("/variable", {"name": variableName})

    def reportSecurityEvent(
        self,
        eventType: str,
        *,
        riskLevel: str = "high",
        confidence: int = 100,
        requestedAction: str = "record_only",
        eventId: str = "",
        actionReason: str = "",
        title: str = "",
        message: str = "",
        evidence: dict | None = None,
        attestation: dict | None = None,
        occurredAt: int | None = None,
        sdkVersion: str = "",
        detectorVersion: str = "",
        platformName: str = "",
    ) -> dict:
        self.ensureSession("/security/report")
        payload = {
            "event_id": securityEventId(eventId),
            "event_type": requiredSecurityText(eventType, "event_type"),
            "risk_level": riskLevel.strip(),
            "confidence": int(confidence),
            "requested_action": securityRequestedAction(requestedAction),
            "action_reason": actionReason.strip(),
            "title": requiredSecurityText(title, "title"),
            "message": requiredSecurityText(message, "message"),
            "evidence": securityObjectPayload(evidence, SECURITY_EVIDENCE_FIELDS, "evidence", True),
            "attestation": securityObjectPayload(attestation, SECURITY_ATTESTATION_FIELDS, "attestation"),
            "occurred_at": int(occurredAt or time.time()),
            "sdk_version": requiredSecurityText(sdkVersion, "sdk_version"),
            "detector_version": requiredSecurityText(detectorVersion, "detector_version"),
            "platform": platformName.strip() or sdkPlatformName(),
        }
        response = self.sendSessionRequest("/security/report", payload)
        if response.get("session_revoked") or response.get("device_disabled") or response.get("card_disabled"):
            self.clearSession()
            return response
        self.applySessionResponse("/security/report", response)
        return response

    def logout(self) -> dict:
        response = self.sessionPost("/logout", {})
        self.clearSession()
        return response

    def hasSession(self) -> bool:
        return bool(self.sessionToken and self.sessionInstallId)

    def token(self) -> str:
        return self.sessionToken

    def setSession(self, token: str, deviceId: str = "", ticket: str = "") -> None:
        normalizedTicket = ticket.strip()
        if normalizedTicket:
            installId = deviceId.strip() or generateDeviceId(self.configValue.appCode)
        else:
            identity = self.ensureIdentity(deviceId.strip())
            installId = identity.installId
        self.sessionToken = token.strip()
        self.sessionTicketValue = normalizedTicket
        self.sessionProofMode = PROOF_MODE_EPHEMERAL_TICKET if normalizedTicket else PROOF_MODE_LOCAL_KEY
        self.sessionInstallId = installId
        self.sessionCounter = 0

    def sessionTicket(self) -> str:
        return self.sessionTicketValue

    def clearSession(self) -> None:
        self.sessionToken = ""
        self.sessionTicketValue = ""
        self.sessionProofMode = ""
        self.sessionInstallId = ""
        self.sessionCounter = 0
        self.loginCardKey = ""
        self.loginInstallId = ""
        self.loginDeviceName = ""

    def sessionPost(self, route: str, payload: dict) -> dict:
        self.ensureSession(route)
        try:
            response = self.sendSessionRequest(route, payload)
        except AuthError as error:
            if not self.shouldRenewSession(route, error):
                raise
            self.renewSession()
            response = self.sendSessionRequest(route, payload)
        self.applySessionResponse(route, response)
        return response

    def post(self, route: str, payload: dict) -> dict:
        algorithm = self.configValue.clientCryptoAlgorithm
        sessionKey = os.urandom(algorithmConfig(algorithm)["keyBytes"])
        timestamp = str(int(time.time()))
        nonce = base64UrlEncode(os.urandom(18))
        body = self.encryptedBody(route, payload, sessionKey, timestamp, nonce)
        try:
            response = json.loads(self.transport.post(route, body, timestamp, nonce))
        except json.JSONDecodeError as error:
            raise AuthError("response is not valid JSON", "INVALID_RESPONSE") from error
        if int(response.get("code", 500)) != self.configValue.successCode:
            raise responseError(response)
        plaintext = aesGcmDecrypt(
            response["data"],
            sessionKey,
            responseAad(route, timestamp, nonce, algorithm).encode("utf-8"),
        )
        return json.loads(plaintext.decode("utf-8"))

    def plainPost(self, route: str, payload: dict) -> dict:
        timestamp = str(int(time.time()))
        nonce = base64UrlEncode(os.urandom(18))
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        try:
            response = json.loads(self.transport.post(route, body, timestamp, nonce, {"X-Plain-Client": "1"}))
        except json.JSONDecodeError as error:
            raise AuthError("response is not valid JSON", "INVALID_RESPONSE") from error
        if int(response.get("code", 500)) != self.configValue.successCode:
            raise responseError(response)
        data = response.get("data")
        if not isinstance(data, dict):
            raise AuthError("response data is not an object", "INVALID_RESPONSE")
        return data

    def encryptedBody(self, route: str, payload: dict, sessionKey: bytes, timestamp: str, nonce: str) -> str:
        algorithm = self.configValue.clientCryptoAlgorithm
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encrypted = aesGcmEncrypt(plaintext, sessionKey, requestAad(route, timestamp, nonce, algorithm).encode("utf-8"))
        envelope = {
            "alg": algorithm,
            "key": base64UrlEncode(rsaEncrypt(self.configValue.clientPublicKey, sessionKey, algorithm)),
            "iv": encrypted["iv"],
            "ciphertext": encrypted["ciphertext"],
            "tag": encrypted["tag"],
        }
        return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))

    def captureLoginContext(self, cardKey: str, installId: str, deviceName: str) -> None:
        self.loginCardKey = requireCardKey(cardKey)
        self.loginInstallId = installId
        self.loginDeviceName = deviceName

    def captureSession(self, response: dict, installId: str) -> None:
        token = str(response.get("token", "")).strip()
        if not token:
            raise AuthError("login response missing token", "SESSION_TOKEN_MISSING")
        self.sessionToken = token
        self.sessionProofMode = normalizedProofMode(response)
        self.sessionTicketValue = str(response.get("session_ticket", "")).strip()
        if self.sessionProofMode == PROOF_MODE_EPHEMERAL_TICKET and not self.sessionTicketValue:
            raise AuthError("login response missing session ticket", "SESSION_TICKET_MISSING")
        self.sessionInstallId = installId
        self.sessionCounter = 0

    def canRenewSession(self) -> bool:
        return bool(self.loginCardKey and self.loginInstallId)

    def ensureSession(self, route: str) -> None:
        if self.hasSession():
            return
        if route != "/logout" and self.canRenewSession():
            self.renewSession()
            return
        raise AuthError("client session is not initialized")

    def sendSessionRequest(self, route: str, payload: dict) -> dict:
        useEphemeralTicket = self.sessionProofMode == PROOF_MODE_EPHEMERAL_TICKET
        identity = None if useEphemeralTicket else self.ensureIdentity(self.sessionInstallId)
        timestamp = int(time.time())
        counter = self.sessionCounter + 1
        requestNonce = base64UrlEncode(os.urandom(18))
        sessionPayload = dict(payload)
        sessionPayload["token"] = self.sessionToken
        sessionPayload["install_id"] = self.sessionInstallId
        sessionPayload["client_version"] = self.configValue.appVersion
        sessionPayload["counter"] = counter
        sessionPayload["request_nonce"] = requestNonce
        sessionPayload["timestamp"] = timestamp
        if useEphemeralTicket:
            if not self.sessionTicketValue:
                raise AuthError("client session ticket is not initialized", "SESSION_TICKET_MISSING")
            sessionPayload["session_ticket"] = self.sessionTicketValue
        else:
            sessionPayload["signature"] = identity.sign(sessionCanonical(
                route,
                self.sessionToken,
                identity.installId,
                counter,
                requestNonce,
                timestamp,
                sessionExtra(route, sessionPayload),
            ))
        response = self.plainPost(route, sessionPayload) if useEphemeralTicket else self.post(route, sessionPayload)
        self.sessionCounter = counter
        return response

    def applySessionResponse(self, route: str, response: dict) -> None:
        if route == "/logout":
            return
        token = response.get("token")
        if not isinstance(token, str) or not token.strip():
            raise AuthError(f"{route} response missing refreshed token", "SESSION_TOKEN_MISSING")
        self.sessionToken = token.strip()
        self.sessionProofMode = normalizedProofMode(response)
        if self.sessionProofMode == PROOF_MODE_EPHEMERAL_TICKET:
            ticket = response.get("session_ticket")
            if not isinstance(ticket, str) or not ticket.strip():
                raise AuthError(f"{route} response missing refreshed session ticket", "SESSION_TICKET_MISSING")
            self.sessionTicketValue = ticket.strip()
        else:
            self.sessionTicketValue = ""

    def shouldRenewSession(self, route: str, error: AuthError) -> bool:
        if route == "/logout" or not self.canRenewSession():
            return False
        recoverableCodes = {
            "SESSION_INVALID",
            "SESSION_TICKET_MISSING",
            "SESSION_TICKET_INVALID",
            "SESSION_TICKET_EXPIRED",
        }
        return retryableGatewayError(error) or error.code in recoverableCodes or any(code in str(error) for code in recoverableCodes)

    def ensureIdentity(self, preferredInstallId: str = "") -> DeviceIdentity:
        installId = preferredInstallId.strip()
        if self.identity is None or not self.identity.ready() or (installId and self.identity.installId != installId):
            self.identity = loadOrCreateDeviceIdentity(self.configValue.appCode, installId)
        return self.identity

    def close(self) -> None:
        self.transport.close()


class HttpTransport:
    def __init__(self, config: Config):
        self.configValue = config
        self.connection = None
        self.parsedUrl = urllib.parse.urlparse(config.apiUrl)
        if self.parsedUrl.scheme not in {"http", "https"} or not self.parsedUrl.hostname:
            raise AuthError("api url must be an absolute http/https url", "INVALID_API_URL")

    def post(self, route: str, body: str, timestamp: str, nonce: str, extraHeaders: dict[str, Any] | None = None) -> str:
        payload = body.encode("utf-8")
        try:
            connection = self.openConnection()
            headers = httpHeaders(self.configValue, route, payload, timestamp, nonce)
            if extraHeaders:
                headers.update(extraHeaders)
            connection.request(
                "POST",
                self.requestTarget(route),
                body=payload,
                headers=headers,
            )
            response = connection.getresponse()
            responseBody = response.read().decode("utf-8", errors="replace")
            if response.status >= 400:
                raise httpStatusError(response.status, responseBody)
            return responseBody
        except AuthError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            self.close()
            raise AuthError(f"network request failed: {error}", "NETWORK_ERROR") from error

    def close(self) -> None:
        if self.connection is None:
            return
        self.connection.close()
        self.connection = None

    def openConnection(self) -> http.client.HTTPConnection:
        if self.connection is not None:
            return self.connection

        port = self.parsedUrl.port
        if self.parsedUrl.scheme == "https":
            self.connection = http.client.HTTPSConnection(
                self.parsedUrl.hostname,
                port,
                timeout=self.configValue.timeoutSeconds,
                context=ssl.create_default_context(),
            )
            return self.connection

        self.connection = http.client.HTTPConnection(
            self.parsedUrl.hostname,
            port,
            timeout=self.configValue.timeoutSeconds,
        )
        return self.connection

    def requestTarget(self, route: str) -> str:
        parsedRouteUrl = urllib.parse.urlparse(routeUrl(self.configValue.apiUrl, route))
        target = parsedRouteUrl.path or "/"
        if parsedRouteUrl.query:
            target += "?" + parsedRouteUrl.query
        return target


def loginCanonical(challengeId: str, installId: str, timestamp: int, machineProfileHash: str, cardHash: str, serverNonce: str) -> str:
    return "\n".join(["POST", "/login", challengeId, installId, str(timestamp), machineProfileHash, cardHash, serverNonce])


def unbindCanonical(installId: str, timestamp: int, cardHash: str) -> str:
    return "\n".join(["POST", "/unbind", installId, str(timestamp), cardHash])


def sessionCanonical(route: str, token: str, installId: str, counter: int, requestNonce: str, timestamp: int, extra: str) -> str:
    return "\n".join(["POST", route, token, installId, str(counter), requestNonce, str(timestamp), sha256Hex(extra)])


def sessionExtra(route: str, payload: dict) -> str:
    if route == "/variable":
        return str(payload.get("name", "")).strip()
    if route == "/security/report":
        return str(payload.get("event_id", "")).strip()
    if route == "/cloud/download-ticket":
        return str(payload.get("file_key", ""))
    return ""


def securityEventId(eventId: str) -> str:
    normalizedEventId = str(eventId or "").strip()
    return normalizedEventId or base64UrlEncode(os.urandom(18))


def securityRequestedAction(value: str) -> str:
    action = str(value or "").strip()
    if action not in SECURITY_REQUESTED_ACTIONS:
        raise AuthError("security report requested action is invalid", "SECURITY_ACTION_INVALID")
    return action


def requiredSecurityText(value: str, fieldName: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise AuthError(f"security report {fieldName} is required", "SECURITY_REPORT_INVALID")
    return text


def securityObjectPayload(value: dict | None, allowedFields: set[str], fieldName: str, required: bool = False) -> dict:
    if value is None:
        if required:
            raise AuthError(f"security report {fieldName} is required", "SECURITY_REPORT_INVALID")
        return {}
    if not isinstance(value, dict):
        raise AuthError("security report evidence and attestation must be objects", "SECURITY_REPORT_INVALID")
    payload = dict(value)
    if required and not payload:
        raise AuthError(f"security report {fieldName} is required", "SECURITY_REPORT_INVALID")
    unknownFields = set(payload) - allowedFields
    if unknownFields:
        raise AuthError(f"security report {fieldName} contains unsupported fields", "SECURITY_REPORT_INVALID")
    return payload


def sdkPlatformName() -> str:
    systemName = platform.system().lower()
    if systemName.startswith("windows"):
        return "windows"
    if systemName == "darwin":
        return "macos"
    if systemName.startswith("linux"):
        return "linux"
    return systemName or "unknown"


def requestAad(route: str, timestamp: str, nonce: str, algorithm: str) -> str:
    return "\n".join(["client-request", route, timestamp, nonce, algorithm])


def responseAad(route: str, timestamp: str, nonce: str, algorithm: str) -> str:
    return "\n".join(["client-response", route, timestamp, nonce, algorithm])


def routeUrl(apiUrl: str, route: str) -> str:
    separator = "&" if "?" in apiUrl else "?"
    return apiUrl + separator + "route=" + urllib.parse.quote(route, safe="")


def cachedNotice(config: Config, loader: Any) -> dict:
    ttlSeconds = max(0, int(config.noticeCacheSeconds))
    if ttlSeconds <= 0:
        return loader()

    cacheKey = noticeCacheKey(config)
    now = time.time()
    with noticeCacheLock:
        cached = noticeCacheValues.get(cacheKey)
        if cached and cached[0] > now:
            return dict(cached[1])
        notice = loader()
        noticeCacheValues[cacheKey] = (now + ttlSeconds, dict(notice))
        return notice


def noticeCacheKey(config: Config) -> str:
    return config.apiUrl + "\n" + config.appCode


def requireCardKey(cardKey: str) -> str:
    card = cardKey.strip()
    if not card:
        raise AuthError("card key is required")
    return card


def resolvedDeviceName(deviceName: str) -> str:
    value = deviceName.strip()
    return value if value else platform.node().strip()[:80]


def machineProfileHash(appCode: str) -> str:
    raw = "\n".join([
        appCode,
        platform.system(),
        platform.release(),
        platform.machine(),
        platform.node(),
        platform.python_version(),
    ])
    return sha256Hex(raw)


def loginPayload(cardKey: str, installId: str, deviceName: str, identity: DeviceIdentity | None, challenge: dict | None, appCode: str, appVersion: str, useEphemeralTicket: bool) -> dict:
    timestamp = int(time.time())
    card = requireCardKey(cardKey)
    profileHash = machineProfileHash(appCode)
    proofMode = PROOF_MODE_EPHEMERAL_TICKET if useEphemeralTicket else PROOF_MODE_LOCAL_KEY
    payload = {
        "card_key": card,
        "challenge_id": ephemeralChallengeId() if useEphemeralTicket else str(challenge["challenge_id"]),
        "install_id": installId,
        "device_name": deviceName,
        "device_key_mode": proofMode,
        "machine_profile_hash": profileHash,
        "client_version": appVersion.strip(),
        "timestamp": timestamp,
    }
    if not useEphemeralTicket:
        payload["signature"] = identity.sign(loginCanonical(
            payload["challenge_id"],
            installId,
            timestamp,
            profileHash,
            cardHash(appCode, card),
            str(challenge["server_nonce"]),
        ))
    return payload


def ephemeralChallengeId() -> str:
    return "ephemeral." + base64UrlEncode(os.urandom(18))


def cardHash(appCode: str, cardKey: str) -> str:
    return sha256Hex(appCode + ":" + cardKey)


def normalizedProofMode(response: dict) -> str:
    mode = str(response.get("proof_mode") or PROOF_MODE_LOCAL_KEY).strip()
    return mode or PROOF_MODE_LOCAL_KEY


def responseError(response: Any, httpStatus: int = 0) -> AuthError:
    if not isinstance(response, dict):
        return AuthError("request failed", "REQUEST_FAILED", httpStatus)
    message = str(response.get("message") or response.get("error") or "request failed")
    code = str(response.get("error") or response.get("code") or "").strip()
    return AuthError(message, code, httpStatus)


def httpStatusError(status: int, responseBody: str) -> AuthError:
    try:
        return responseError(json.loads(responseBody), status)
    except json.JSONDecodeError:
        return AuthError(f"HTTP status {status}: {responseBody}", "HTTP_ERROR", status)


def retryableLoginError(error: AuthError) -> bool:
    return error.code in {"NETWORK_ERROR", "DB_ERROR"} or retryableGatewayError(error)


def retryableGatewayError(error: AuthError) -> bool:
    return error.httpStatus in {502, 503, 504}


def httpHeaders(config: Config, route: str, body: bytes, timestamp: str, nonce: str) -> dict[str, Any]:
    return {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Connection": "keep-alive",
        "X-App-Code": config.appCode,
        "X-Api-Token": config.apiToken,
        "X-Api-Call-Id": config.callId(route),
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
    }
