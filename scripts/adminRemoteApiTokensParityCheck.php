<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class AdminRemoteApiTokensParityCheck
{
    private const PREFIX = 'E2E_REMOTE_API_';

    public function __construct(
        private readonly SpringMySQLi $database,
        private readonly string $systemKey,
        private readonly string $phpBaseUrl,
        private readonly string $rustBaseUrl
    ) {
    }

    public function run(): int
    {
        if (in_array('--cleanup-only', $_SERVER['argv'] ?? [], true)) {
            $this->cleanup();
            echo "CLEANED admin remote api token fixtures\n";
            return 0;
        }
        if (in_array('--browser-fixture', $_SERVER['argv'] ?? [], true)) {
            return $this->runBrowserFixture();
        }

        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $session = $this->createAdminSession();
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl), $session);
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl), $session);
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'adminRemoteApiTokens');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK admin remote api tokens\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function runBrowserFixture(): int
    {
        $this->cleanup();
        $target = $this->createTarget('browser', $this->rustBaseUrl);
        $admin = $this->createAdminLoginCookie();
        $secret = Crypto::token(32);
        $accessKey = Crypto::token(24);
        $tokenName = $target['tokenPrefix'] . 'browser';
        $tokenId = $this->insertRemoteApiToken($tokenName, $accessKey, $secret, $admin['username']);
        $this->insertRemoteApiLog($tokenId, $accessKey, '/remote/apps/api/get', $target['appId'], 'success', '', 'ok');
        $this->insertRemoteApiLog(null, $accessKey, '/remote/apps/api/get', null, 'failed', 'REMOTE_API_BAD_SIGNATURE', '远程 API 请求签名错误');
        echo $this->json([
            'baseUrl' => $this->rustBaseUrl,
            'consoleUrl' => rtrim($this->rustBaseUrl, '/') . '/admin/console/#remoteApi',
            'logsUrl' => rtrim($this->rustBaseUrl, '/') . '/admin/console/#remoteApiLogs',
            'cookieName' => 'sub_admin_token',
            'cookieValue' => $admin['cookie'],
            'tokenName' => $tokenName,
            'accessKey' => $accessKey,
        ]) . "\n";
        return 0;
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $suffix = substr(strtoupper($name), 0, 3) . '_' . strtoupper($this->randomAlpha(6));
        $appCode = self::PREFIX . 'APP_' . $suffix;
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'tokenPrefix' => self::PREFIX . 'TOKEN_' . $suffix . '_',
            'appCode' => $appCode,
            'appId' => $this->insertApp($appCode, 'Parity Remote API Target'),
        ];
    }

    private function runTarget(array $target, array $session): array
    {
        $steps = [];
        $steps['emptyList'] = $this->normalizeTokenList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/list',
            ['keyword' => $target['tokenPrefix']]
        )), $target);

        $create = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/create',
            [
                'name' => $target['tokenPrefix'] . 'primary',
                'expires_at' => date('Y-m-d\TH:i', time() + 7200),
                'ip_allowlist' => "127.0.0.1, 127.0.0.0/24、::1\n127.0.0.1",
            ]
        ));
        $primaryToken = is_array($create['token'] ?? null) ? $create['token'] : [];
        $primaryId = $this->positiveId($primaryToken['id'] ?? null, 'primary token id');
        $primaryAccessKey = (string)($primaryToken['access_key'] ?? '');
        $primarySecret = (string)($create['secret'] ?? '');
        $steps['createPrimary'] = $this->normalizeCreate($create, $target);
        $steps['secretPrimary'] = $this->normalizeSecret($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/secret',
            ['token_id' => $primaryId]
        )), $target, $primarySecret);
        $steps['listAfterCreate'] = $this->normalizeTokenList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/list',
            ['keyword' => $target['tokenPrefix']]
        )), $target);
        $steps['searchByAccessKey'] = $this->normalizeTokenList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/list',
            ['keyword' => $primaryAccessKey]
        )), $target);

        $steps['remoteSuccess'] = $this->normalizeRemoteResponse($this->remoteRequest(
            $target,
            '/remote/apps/api/get',
            ['app_code' => $target['appCode']],
            $primaryAccessKey,
            $primarySecret
        ));
        $steps['remoteBadSignature'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/apps/api/get',
            ['app_code' => $target['appCode']],
            $primaryAccessKey,
            $primarySecret,
            ['signature' => str_repeat('0', 64)]
        ));
        $steps['statusDisable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/status',
            ['token_id' => $primaryId, 'status' => 'false']
        ));
        $steps['remoteDisabled'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/apps/api/get',
            ['app_code' => $target['appCode']],
            $primaryAccessKey,
            $primarySecret
        ));
        $steps['listDisabled'] = $this->normalizeTokenList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/list',
            ['keyword' => $target['tokenPrefix'], 'status' => 0]
        )), $target);
        $steps['statusEnable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/status',
            ['token_id' => $primaryId, 'status' => true]
        ));

        $logData = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/logs/list',
            ['keyword' => $primaryAccessKey]
        ));
        $steps['logList'] = $this->normalizeLogList($logData, $target, $primaryAccessKey);
        $logIds = $this->rawLogIds($logData);
        $steps['deleteOneLog'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/logs/delete',
            ['log_id' => $logIds[0] ?? 0]
        ));
        $steps['clearLogs'] = $this->normalizeDeletedAtLeast($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/logs/clear',
            ['confirm' => 'CLEAR_REMOTE_API_LOGS']
        )), 2);

        $deleteCreate = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/create',
            ['name' => $target['tokenPrefix'] . 'delete']
        ));
        $deleteId = $this->positiveId($deleteCreate['token']['id'] ?? null, 'delete token id');
        $steps['deleteToken'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/delete',
            ['token_id' => $deleteId]
        ));
        $steps['secretAfterDeleteError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/remote-api/tokens/secret',
            ['token_id' => $deleteId]
        ));

        foreach ($this->errorPayloads($target) as $name => [$route, $payload]) {
            $steps[$name] = $this->normalizeError($this->adminRequest($target, $session, $route, $payload));
        }

        return ['steps' => $steps];
    }

    private function errorPayloads(array $target): array
    {
        return [
            'missingNameError' => ['/admin/remote-api/tokens/create', ['name' => '']],
            'invalidExpiresError' => [
                '/admin/remote-api/tokens/create',
                ['name' => $target['tokenPrefix'] . 'badExpires', 'expires_at' => '2026-02-30'],
            ],
            'invalidIpRuleError' => [
                '/admin/remote-api/tokens/create',
                ['name' => $target['tokenPrefix'] . 'badIp', 'ip_allowlist' => '999.1.1.1'],
            ],
            'nestedIpRuleError' => [
                '/admin/remote-api/tokens/create',
                ['name' => $target['tokenPrefix'] . 'nestedIp', 'ip_allowlist' => [['127.0.0.1']]],
            ],
            'invalidIdError' => ['/admin/remote-api/tokens/secret', ['token_id' => 'abc']],
            'missingTokenError' => ['/admin/remote-api/tokens/secret', ['token_id' => 922337203685477]],
            'clearLogsConfirmError' => ['/admin/remote-api/logs/clear', ['confirm' => 'NO']],
        ];
    }

    private function normalizeCreate(array $data, array $target): array
    {
        return [
            'created' => (bool)($data['created'] ?? false),
            'token' => $this->normalizeToken($data['token'] ?? [], $target),
            'secret' => $this->secretState($data['secret'] ?? null),
        ];
    }

    private function normalizeSecret(array $data, array $target, string $expectedSecret): array
    {
        return [
            'token' => $this->normalizeToken($data['token'] ?? [], $target),
            'secret' => $this->secretState($data['secret'] ?? null),
            'matchesCreatedSecret' => (string)($data['secret'] ?? '') === $expectedSecret,
        ];
    }

    private function normalizeTokenList(array $data, array $target): array
    {
        $rows = [];
        foreach (is_array($data['tokens'] ?? null) ? $data['tokens'] : [] as $row) {
            $rows[] = $this->normalizeToken($row, $target);
        }
        usort($rows, static fn(array $left, array $right): int => strcmp($left['name'], $right['name']));
        return $rows;
    }

    private function normalizeToken(mixed $row, array $target): array
    {
        $row = is_array($row) ? $row : [];
        return [
            'keys' => $this->sortedKeys($row),
            'id' => $this->dynamicId($row['id'] ?? null),
            'name' => $this->normalizeName((string)($row['name'] ?? ''), $target),
            'access_key' => $this->accessKeyState($row['access_key'] ?? null),
            'status' => $this->typedValue($row['status'] ?? null),
            'expires_at_state' => trim((string)($row['expires_at'] ?? '')) === '' ? 'empty' : 'present',
            'ip_allowlist' => array_values(array_map('strval', is_array($row['ip_allowlist'] ?? null) ? $row['ip_allowlist'] : [])),
            'last_used_at_state' => trim((string)($row['last_used_at'] ?? '')) === '' ? 'empty' : 'present',
            'last_ip' => $this->normalizeIp((string)($row['last_ip'] ?? '')),
            'created_by_state' => str_starts_with((string)($row['created_by'] ?? ''), self::PREFIX . 'admin_') ? 'parity_admin' : 'other',
            'created_at_state' => trim((string)($row['created_at'] ?? '')) === '' ? 'empty' : 'present',
            'updated_at_state' => trim((string)($row['updated_at'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function normalizeLogList(array $data, array $target, string $accessKey): array
    {
        $rows = [];
        foreach (is_array($data['logs'] ?? null) ? $data['logs'] : [] as $row) {
            $rows[] = $this->normalizeLog($row, $target, $accessKey);
        }
        usort($rows, static function (array $left, array $right): int {
            return strcmp($left['status'] . $left['error_code'], $right['status'] . $right['error_code']);
        });
        return $rows;
    }

    private function normalizeLog(mixed $row, array $target, string $accessKey): array
    {
        $row = is_array($row) ? $row : [];
        return [
            'keys' => $this->sortedKeys($row),
            'id' => $this->dynamicId($row['id'] ?? null),
            'token_id' => $this->nullableId($row['token_id'] ?? null),
            'token_name' => $this->normalizeName((string)($row['token_name'] ?? ''), $target),
            'access_key' => (string)($row['access_key'] ?? '') === $accessKey ? '<access_key>' : 'other',
            'route' => (string)($row['route'] ?? ''),
            'target_app_id' => $this->targetAppId($row['target_app_id'] ?? null),
            'app_code' => (string)($row['app_code'] ?? '') === $target['appCode'] ? '<app>' : (string)($row['app_code'] ?? ''),
            'app_name' => (string)($row['app_name'] ?? ''),
            'status' => (string)($row['status'] ?? ''),
            'error_code' => (string)($row['error_code'] ?? ''),
            'message_state' => trim((string)($row['message'] ?? '')) === '' ? 'empty' : 'present',
            'ip' => $this->normalizeIp((string)($row['ip'] ?? '')),
            'created_at_state' => trim((string)($row['created_at'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function normalizeRemoteResponse(array $step): array
    {
        $body = is_array($step['body'] ?? null) ? $step['body'] : [];
        return [
            'httpStatus' => (int)($step['httpStatus'] ?? 0),
            'code' => (int)($body['code'] ?? -1),
            'hasData' => is_array($body['data'] ?? null),
        ];
    }

    private function normalizeError(array $step): array
    {
        $body = is_array($step['body'] ?? null) ? $step['body'] : [];
        return [
            'httpStatus' => (int)($step['httpStatus'] ?? 0),
            'code' => (int)($body['code'] ?? -1),
            'error' => (string)($body['error'] ?? ''),
        ];
    }

    private function normalizeDeletedAtLeast(array $data, int $minimum): array
    {
        return [
            'deleted_seeded_rows' => (int)($data['deleted'] ?? -1) >= $minimum,
        ];
    }

    private function adminRequest(array $target, array $session, string $route, array $payload): array
    {
        $timestamp = (string)time();
        $nonce = Crypto::token(18);
        $plaintext = $this->json($payload);
        $body = $this->json(Crypto::encryptGcm(
            $plaintext,
            $session['rawKey'],
            "POST\n{$route}\n{$timestamp}\n{$nonce}"
        ));
        $signature = RequestSigner::sign($session['rawKey'], [
            'method' => 'POST',
            'route' => $route,
            'timestamp' => $timestamp,
            'nonce' => $nonce,
            'body' => $body,
        ]);
        $response = $this->httpJson(
            $target['baseUrl'] . '/api/v1/index.php?route=' . rawurlencode($route),
            [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'X-Admin-Session' => $session['token'],
                'X-Timestamp' => $timestamp,
                'X-Nonce' => $nonce,
                'X-Signature' => $signature,
            ],
            $body
        );
        return $this->decryptAdminResponse($response, $session, $route, $nonce);
    }

    private function remoteRequest(
        array $target,
        string $route,
        array $payload,
        string $accessKey,
        string $secret,
        array $overrides = []
    ): array {
        $timestamp = (string)($overrides['timestamp'] ?? time());
        $nonce = (string)($overrides['nonce'] ?? Crypto::token(18));
        $body = $this->json($payload);
        $signature = (string)($overrides['signature'] ?? RequestSigner::sign($secret, [
            'method' => 'POST',
            'route' => $route,
            'timestamp' => $timestamp,
            'nonce' => $nonce,
            'body' => $body,
        ]));
        return $this->httpJson(
            $target['baseUrl'] . '/api/v1/index.php?route=' . rawurlencode($route),
            [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'X-Remote-Access-Key' => $accessKey,
                'X-Timestamp' => $timestamp,
                'X-Nonce' => $nonce,
                'X-Signature' => $signature,
            ],
            $body
        );
    }

    private function decryptAdminResponse(array $response, array $session, string $route, string $nonce): array
    {
        $body = $response['body'];
        if (($response['httpStatus'] ?? 0) === 200
            && is_array($body)
            && ($body['code'] ?? null) === 0
            && (($body['data']['encrypted'] ?? false) === true)
        ) {
            $body['data'] = json_decode(Crypto::decryptGcm(
                $body['data']['payload'],
                $session['rawKey'],
                "RESPONSE\n{$route}\n{$nonce}"
            ), true);
        }
        return [
            'route' => $route,
            'httpStatus' => $response['httpStatus'],
            'body' => $body,
        ];
    }

    private function httpJson(string $url, array $headers, string $content): array
    {
        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headerLines),
                'content' => $content,
                'ignore_errors' => true,
                'timeout' => 10,
            ],
        ]);
        $raw = @file_get_contents($url, false, $context);
        $body = json_decode(is_string($raw) ? $raw : '', true);
        return [
            'httpStatus' => $this->httpStatus($http_response_header ?? []),
            'body' => is_array($body) ? $body : ['error' => 'NON_JSON_RESPONSE', 'raw' => $raw],
        ];
    }

    private function successData(array $step): array
    {
        $body = $step['body'];
        if (($step['httpStatus'] ?? 0) !== 200 || !is_array($body) || ($body['code'] ?? null) !== 0) {
            throw new RuntimeException('admin request failed: ' . $this->json($step));
        }
        $data = $body['data'] ?? [];
        if (!is_array($data)) {
            throw new RuntimeException('admin response data is not object: ' . $this->json($step));
        }
        return $data;
    }

    private function createAdminSession(): array
    {
        $username = self::PREFIX . 'admin_' . strtolower($this->randomAlpha(8));
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity Remote API Admin', $this->rustBaseUrl]
        );
        $token = Crypto::token();
        $keyText = Crypto::encodeBase64Url(random_bytes(32));
        $this->exec(
            'INSERT INTO `auth_admin_sessions` (`token_hash`, `key_cipher`, `ip`, `admin_username`, `expires_at`, `status`) VALUES (?, ?, ?, ?, ?, ?)',
            [Crypto::sha256($token), Crypto::encryptSecret($keyText, $this->systemKey), '127.0.0.1', $username, date('Y-m-d H:i:s', time() + 3600), 1]
        );
        return ['token' => $token, 'rawKey' => Crypto::decodeBase64Url($keyText)];
    }

    private function createAdminLoginCookie(): array
    {
        $username = self::PREFIX . 'browser_admin_' . strtolower($this->randomAlpha(6));
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity Remote API Browser', $this->rustBaseUrl]
        );
        $session = md5($username . $passwordHash . hash('sha256', $this->systemKey));
        return [
            'username' => $username,
            'cookie' => Crypto::encryptProtectedText($username . "\t" . $session, $this->systemKey),
        ];
    }

    private function insertApp(string $appCode, string $name): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appCode,
                ClientApiConfig::generateToken(),
                $name,
                1,
                50,
                300,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                $this->json(ClientApiConfig::defaults()),
                '1.0.0',
                'local_key_v1',
                'rsa_oaep_aes_256_gcm',
                '',
                '',
                'admin remote api token parity',
            ]
        );
    }

    private function insertRemoteApiToken(string $name, string $accessKey, string $secret, string $createdBy): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_remote_api_tokens` (`name`, `access_key`, `secret_cipher`, `status`, `expires_at`, `ip_allowlist_json`, `created_by`) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [
                $name,
                $accessKey,
                Crypto::encryptSecret($secret, $this->systemKey),
                1,
                date('Y-m-d H:i:s', time() + 7200),
                $this->json(['127.0.0.1']),
                $createdBy,
            ]
        );
    }

    private function insertRemoteApiLog(
        ?int $tokenId,
        string $accessKey,
        string $route,
        ?int $targetAppId,
        string $status,
        string $errorCode,
        string $message
    ): void {
        $this->exec(
            'INSERT INTO `auth_remote_api_logs` (`token_id`, `access_key`, `route`, `target_app_id`, `request_hash`, `status`, `error_code`, `message`, `ip`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$tokenId, $accessKey, $route, $targetAppId, hash('sha256', $message), $status, $errorCode, $message, '127.0.0.1']
        );
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
        $this->deleteRemoteApiRows();
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . 'APP_%']);
        foreach ($rows as $row) {
            $this->deleteAppRows((int)$row['id']);
        }
        $this->exec('DELETE FROM `sub_admin` WHERE `username` LIKE ?', [self::PREFIX . '%']);
    }

    private function deleteAdminSessions(): void
    {
        if ($this->tableExists('auth_admin_nonces')) {
            $sessions = $this->database->selectV2('SELECT `id` FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', [self::PREFIX . '%']);
            foreach ($sessions as $session) {
                $this->exec('DELETE FROM `auth_admin_nonces` WHERE `session_id` = ?', [(int)$session['id']]);
            }
        }
        $this->exec('DELETE FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', [self::PREFIX . '%']);
    }

    private function deleteRemoteApiRows(): void
    {
        $tokens = $this->database->selectV2('SELECT `id`, `access_key` FROM `auth_remote_api_tokens` WHERE `name` LIKE ?', [self::PREFIX . 'TOKEN_%']);
        $tokenIds = $this->columnInts($tokens, 'id');
        $accessKeys = $this->columnStrings($tokens, 'access_key');
        if ($tokenIds !== []) {
            $this->execIn('DELETE FROM `auth_remote_api_nonces` WHERE `token_id` IN (%s)', $tokenIds);
            $this->execIn('DELETE FROM `auth_remote_api_logs` WHERE `token_id` IN (%s)', $tokenIds);
        }
        if ($accessKeys !== []) {
            $this->execIn('DELETE FROM `auth_remote_api_logs` WHERE `access_key` IN (%s)', $accessKeys);
        }
        $this->exec('DELETE FROM `auth_remote_api_tokens` WHERE `name` LIKE ?', [self::PREFIX . 'TOKEN_%']);
    }

    private function deleteAppRows(int $appId): void
    {
        foreach ([
            'auth_message_actions',
            'auth_messages',
            'auth_security_reports',
            'auth_security_policies',
            'auth_audit_logs',
            'auth_sessions',
            'auth_devices',
            'auth_accounts',
            'auth_login_challenges',
            'auth_card_search_tokens',
            'auth_cards',
            'auth_remote_configs',
        ] as $table) {
            if ($this->tableExists($table)) {
                $this->exec("DELETE FROM `{$table}` WHERE `app_id` = ?", [$appId]);
            }
        }
        $this->exec('DELETE FROM `auth_apps` WHERE `id` = ?', [$appId]);
    }

    private function rawLogIds(array $data): array
    {
        $ids = [];
        foreach (is_array($data['logs'] ?? null) ? $data['logs'] : [] as $row) {
            $id = (int)($row['id'] ?? 0);
            if ($id > 0) {
                $ids[] = $id;
            }
        }
        return $ids;
    }

    private function positiveId(mixed $value, string $label): int
    {
        $id = (int)$value;
        if ($id <= 0) {
            throw new RuntimeException("missing {$label}: " . $this->json($value));
        }
        return $id;
    }

    private function dynamicId(mixed $value): array
    {
        $id = (int)$value;
        return [
            'type' => get_debug_type($value),
            'state' => $id > 0 ? 'present' : 'missing',
        ];
    }

    private function nullableId(mixed $value): array
    {
        $text = trim((string)$value);
        if ($value === null || $text === '') {
            return ['type' => get_debug_type($value), 'state' => 'empty'];
        }
        return [
            'type' => get_debug_type($value),
            'state' => ((int)$value) > 0 ? 'present' : 'invalid',
        ];
    }

    private function targetAppId(mixed $value): array
    {
        $text = trim((string)$value);
        if ($value === null || $text === '') {
            return ['type' => get_debug_type($value), 'state' => 'empty'];
        }
        return ['type' => get_debug_type($value), 'state' => ((int)$value) > 0 ? 'present' : 'invalid'];
    }

    private function typedValue(mixed $value): array
    {
        return ['type' => get_debug_type($value), 'value' => $value];
    }

    private function secretState(mixed $value): array
    {
        $secret = (string)$value;
        return [
            'type' => get_debug_type($value),
            'length' => strlen($secret),
            'token_text' => preg_match('/^[A-Za-z0-9_-]+$/', $secret) === 1,
        ];
    }

    private function accessKeyState(mixed $value): array
    {
        $accessKey = (string)$value;
        return [
            'type' => get_debug_type($value),
            'length' => strlen($accessKey),
            'token_text' => preg_match('/^[A-Za-z0-9_-]+$/', $accessKey) === 1,
        ];
    }

    private function normalizeName(string $name, array $target): string
    {
        if ($name === '') {
            return '';
        }
        return str_starts_with($name, $target['tokenPrefix'])
            ? '<token>.' . substr($name, strlen($target['tokenPrefix']))
            : $name;
    }

    private function normalizeIp(string $ip): string
    {
        return $ip === '127.0.0.1' || $ip === '::1' ? '<local>' : $ip;
    }

    private function sortedKeys(array $row): array
    {
        $keys = array_map('strval', array_keys($row));
        sort($keys);
        return $keys;
    }

    private function columnInts(array $rows, string $key): array
    {
        return array_values(array_filter(array_map(
            static fn(array $row): int => (int)($row[$key] ?? 0),
            $rows
        ), static fn(int $value): bool => $value > 0));
    }

    private function columnStrings(array $rows, string $key): array
    {
        return array_values(array_filter(array_map(
            static fn(array $row): string => (string)($row[$key] ?? ''),
            $rows
        ), static fn(string $value): bool => $value !== ''));
    }

    private function execIn(string $sql, array $values): void
    {
        if ($values === []) {
            return;
        }
        $placeholders = implode(', ', array_fill(0, count($values), '?'));
        $this->exec(sprintf($sql, $placeholders), array_values($values));
    }

    private function exec(string $sql, array $params): int|string
    {
        $result = $this->database->exec($sql, $params);
        if ($result === false) {
            throw new RuntimeException($this->database->getError() ?: 'database statement failed');
        }
        return $result;
    }

    private function tableExists(string $table): bool
    {
        return is_array($this->database->selectRowV2('SHOW TABLES LIKE ?', [$table]));
    }

    private function diff(mixed $left, mixed $right, string $path): array
    {
        if (is_array($left) && is_array($right)) {
            $keys = array_unique(array_merge(array_keys($left), array_keys($right)));
            sort($keys);
            $diffs = [];
            foreach ($keys as $key) {
                $childPath = $path . '.' . (string)$key;
                if (!array_key_exists($key, $left)) {
                    $diffs[] = "{$childPath} missing on php side";
                    continue;
                }
                if (!array_key_exists($key, $right)) {
                    $diffs[] = "{$childPath} missing on rust side";
                    continue;
                }
                array_push($diffs, ...$this->diff($left[$key], $right[$key], $childPath));
            }
            return $diffs;
        }
        if ($left !== $right) {
            return [$path . ' php=' . $this->jsonScalar($left) . ' rust=' . $this->jsonScalar($right)];
        }
        return [];
    }

    private function httpStatus(array $headers): int
    {
        foreach ($headers as $header) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', (string)$header, $matches) === 1) {
                return (int)$matches[1];
            }
        }
        return 0;
    }

    private function printResult(string $name, array $result): void
    {
        echo strtoupper($name) . ' ' . $this->json($result) . "\n";
    }

    private function json(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private function jsonScalar(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private function randomAlpha(int $length): string
    {
        $value = '';
        while (strlen($value) < $length) {
            $value .= preg_replace('/[^A-Za-z0-9]/', '', base64_encode(random_bytes($length))) ?: '';
        }
        return substr($value, 0, $length);
    }
}

if (!$DB instanceof SpringMySQLi) {
    fwrite(STDERR, "DB_NOT_CONFIGURED\n");
    exit(1);
}
if (!defined('SYS_KEY') || (string)SYS_KEY === '') {
    fwrite(STDERR, "SYS_KEY_MISSING\n");
    exit(1);
}

$check = new AdminRemoteApiTokensParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
