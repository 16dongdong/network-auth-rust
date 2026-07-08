<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;

final class RemoteApiConfigParityCheck
{
    private const PREFIX = 'E2E_RCFG_';

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
            echo "CLEANED remote api config fixtures\n";
            return 0;
        }

        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl));
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl));
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'remoteApiConfig');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK remote api config\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $suffix = strtoupper(substr($name, 0, 3)) . '_' . strtoupper($this->randomAlpha(6));
        $appCode = self::PREFIX . 'APP_' . $suffix;
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => $appCode,
            'appId' => $this->insertApp($appCode, 'Remote API Config'),
            'tokenName' => self::PREFIX . 'TOKEN_' . $suffix,
        ];
    }

    private function runTarget(array $target): array
    {
        $secret = Crypto::token(32);
        $accessKey = Crypto::token(24);
        $tokenId = $this->insertRemoteApiToken($target['tokenName'], $accessKey, $secret);
        $this->seedRemoteConfig($target['appId']);
        $steps = [];

        $steps['getSeeded'] = $this->normalizeConfig($this->successData($this->remoteRequest(
            $target,
            '/remote/config/get',
            ['app_code' => $target['appCode']],
            $accessKey,
            $secret
        )));
        $steps['setTruthy'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/config/set',
            [
                'app_code' => $target['appCode'],
                'notice' => "远程配置通知\n第二行",
                'version' => '8.6.1',
                'force_update' => 'yes',
                'download_url' => 'https://example.test/download/client.zip',
            ],
            $accessKey,
            $secret
        ));
        $steps['getAfterTruthy'] = $this->normalizeConfig($this->successData($this->remoteRequest(
            $target,
            '/remote/config/get',
            ['app_code' => $target['appCode']],
            $accessKey,
            $secret
        )));
        $steps['rawAfterTruthy'] = $this->remoteConfigRawFact($target['appId']);
        $steps['setZero'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/config/set',
            [
                'app_code' => $target['appCode'],
                'notice' => '',
                'version' => '8.6.2',
                'force_update' => '0',
                'download_url' => '',
            ],
            $accessKey,
            $secret
        ));
        $steps['getAfterZero'] = $this->normalizeConfig($this->successData($this->remoteRequest(
            $target,
            '/remote/config/get',
            ['app_code' => $target['appCode']],
            $accessKey,
            $secret
        )));
        $steps['rawAfterZero'] = $this->remoteConfigRawFact($target['appId']);
        $steps['missingAppError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/config/get',
            ['app_code' => self::PREFIX . 'MISSING_' . $target['name']],
            $accessKey,
            $secret
        ));
        $steps['appIdOnlyError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/config/get',
            ['app_id' => $target['appId']],
            $accessKey,
            $secret
        ));
        $steps['logs'] = $this->remoteLogFacts($accessKey, $target);
        $steps['audits'] = $this->auditFacts($target);
        $steps['tokenTouched'] = $this->tokenTouchedFact($tokenId);

        return ['steps' => $steps];
    }

    private function remoteRequest(
        array $target,
        string $route,
        array $payload,
        string $accessKey,
        string $secret
    ): array {
        $timestamp = (string)time();
        $nonce = Crypto::token(18);
        $body = $this->json($payload);
        $signature = RequestSigner::sign($secret, [
            'method' => 'POST',
            'route' => $route,
            'timestamp' => $timestamp,
            'nonce' => $nonce,
            'body' => $body,
        ]);
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
            'body' => is_array($body) ? $body : ['raw' => is_string($raw) ? $raw : ''],
        ];
    }

    private function successData(array $response): array
    {
        $body = is_array($response['body'] ?? null) ? $response['body'] : [];
        if ((int)($response['httpStatus'] ?? 0) !== 200 || (int)($body['code'] ?? -1) !== 0 || !is_array($body['data'] ?? null)) {
            throw new RuntimeException('unexpected success response: ' . $this->json($response));
        }
        return $body['data'];
    }

    private function normalizeConfig(array $data): array
    {
        $config = is_array($data['config'] ?? null) ? $data['config'] : [];
        return [
            'notice' => (string)($config['notice'] ?? ''),
            'version' => (string)($config['version'] ?? ''),
            'force_update' => (int)($config['force_update'] ?? -1),
            'download_url' => (string)($config['download_url'] ?? ''),
        ];
    }

    private function normalizeError(array $response): array
    {
        $body = is_array($response['body'] ?? null) ? $response['body'] : [];
        return [
            'httpStatus' => (int)($response['httpStatus'] ?? 0),
            'code' => (int)($body['code'] ?? -1),
            'error' => (string)($body['error'] ?? ''),
        ];
    }

    private function remoteConfigRawFact(int $appId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `notice`, `config_json`, `variables_json`, `version`, `force_update`, `download_url`, `status` FROM `auth_remote_configs` WHERE `app_id` = ?',
            [$appId]
        );
        return [
            'notice' => (string)($row['notice'] ?? ''),
            'config_json' => (string)($row['config_json'] ?? ''),
            'variables_json' => (string)($row['variables_json'] ?? ''),
            'version' => (string)($row['version'] ?? ''),
            'force_update' => (int)($row['force_update'] ?? -1),
            'download_url' => (string)($row['download_url'] ?? ''),
            'status' => (int)($row['status'] ?? -1),
        ];
    }

    private function remoteLogFacts(string $accessKey, array $target): array
    {
        $rows = $this->database->selectV2(
            'SELECT `route`, `target_app_id`, `status`, `error_code`, `message`, `ip` FROM `auth_remote_api_logs` WHERE `access_key` = ? ORDER BY `id` ASC',
            [$accessKey]
        );
        $facts = [];
        foreach ($rows as $row) {
            $facts[] = [
                'route' => (string)($row['route'] ?? ''),
                'target_app_id' => $this->targetAppId($row['target_app_id'] ?? null, $target),
                'status' => (string)($row['status'] ?? ''),
                'error_code' => (string)($row['error_code'] ?? ''),
                'message_state' => trim((string)($row['message'] ?? '')) === '' ? 'empty' : 'present',
                'ip' => $this->normalizeIp((string)($row['ip'] ?? '')),
            ];
        }
        return $facts;
    }

    private function auditFacts(array $target): array
    {
        $rows = $this->database->selectV2(
            'SELECT `app_id`, `action`, `message`, `ip` FROM `auth_audit_logs` WHERE `action` = ? AND `message` LIKE ? ORDER BY `id` ASC',
            ['remote_config_set', '%Token：' . $target['tokenName'] . '%']
        );
        $facts = [];
        foreach ($rows as $row) {
            $facts[] = [
                'app_id' => $this->targetAppId($row['app_id'] ?? null, $target),
                'action' => (string)($row['action'] ?? ''),
                'message_state' => str_contains((string)($row['message'] ?? ''), $target['tokenName']) ? 'token_name' : 'other',
                'ip' => $this->normalizeIp((string)($row['ip'] ?? '')),
            ];
        }
        return $facts;
    }

    private function tokenTouchedFact(int $tokenId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `last_used_at`, `last_ip` FROM `auth_remote_api_tokens` WHERE `id` = ?',
            [$tokenId]
        );
        return [
            'last_used_at_state' => trim((string)($row['last_used_at'] ?? '')) === '' ? 'empty' : 'present',
            'last_ip' => $this->normalizeIp((string)($row['last_ip'] ?? '')),
        ];
    }

    private function insertApp(string $appCode, string $name): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appCode,
                Crypto::token(32),
                $name,
                1,
                3,
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
                '[]',
                '1.0.0',
                'local_key_v1',
                'rsa_oaep_aes_256_gcm',
                '',
                '',
                'remote api config parity',
            ]
        );
    }

    private function seedRemoteConfig(int $appId): void
    {
        $this->exec(
            'INSERT INTO `auth_remote_configs` (`app_id`, `notice`, `config_json`, `variables_json`, `version`, `force_update`, `download_url`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, 'seed notice', '{"seed":true}', '{"keep":"yes"}', '1.2.3', 1, 'https://example.test/seed.zip', 1]
        );
    }

    private function insertRemoteApiToken(string $name, string $accessKey, string $secret): int
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
                self::PREFIX . 'seed',
            ]
        );
    }

    private function cleanup(): void
    {
        $this->deleteRemoteApiRows();
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . 'APP_%']);
        foreach ($rows as $row) {
            $this->deleteAppRows((int)$row['id']);
        }
        $this->exec('DELETE FROM `auth_audit_logs` WHERE `message` LIKE ?', ['%Token：' . self::PREFIX . 'TOKEN_%']);
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
            'auth_remote_variable_apps',
            'auth_remote_configs',
        ] as $table) {
            if ($this->tableExists($table)) {
                $this->exec("DELETE FROM `{$table}` WHERE `app_id` = ?", [$appId]);
            }
        }
        $this->exec('DELETE FROM `auth_apps` WHERE `id` = ?', [$appId]);
    }

    private function targetAppId(mixed $value, ?array $target = null): string
    {
        $id = (int)$value;
        if ($id <= 0) {
            return 'null';
        }
        if ($target !== null && $id === (int)$target['appId']) {
            return '<app>';
        }
        return '<other>';
    }

    private function normalizeIp(string $ip): string
    {
        return $ip === '127.0.0.1' || $ip === '::1' ? '<local>' : $ip;
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
        return $left === $right ? [] : [$path . ' php=' . $this->jsonScalar($left) . ' rust=' . $this->jsonScalar($right)];
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

$check = new RemoteApiConfigParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
