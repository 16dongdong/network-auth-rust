<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class AdminAppLifecycleParityCheck
{
    private const PREFIX = 'E2E_APP_LIFE_';

    public function __construct(
        private readonly SpringMySQLi $database,
        private readonly string $systemKey,
        private readonly string $phpBaseUrl,
        private readonly string $rustBaseUrl
    ) {
    }

    public function run(): int
    {
        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl));
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl));
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'adminAppLifecycle');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK admin app lifecycle\n";
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
        $labelPrefix = self::PREFIX . $suffix . '_';
        $apps = [
            'single' => $this->insertApp($labelPrefix . 'SINGLE', $labelPrefix . '单应用'),
            'batchOne' => $this->insertApp($labelPrefix . 'BATCH_A', $labelPrefix . '批量A'),
            'batchTwo' => $this->insertApp($labelPrefix . 'BATCH_B', $labelPrefix . '批量B'),
            'deleteOne' => $this->insertApp($labelPrefix . 'DELETE_A', $labelPrefix . '删除A'),
            'deleteTwo' => $this->insertApp($labelPrefix . 'DELETE_B', $labelPrefix . '删除B'),
        ];
        $this->seedDeleteDependencies($apps['deleteOne']);
        $this->seedDeleteDependencies($apps['deleteTwo']);
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'labelPrefix' => $labelPrefix,
            'usernamePrefix' => 'al' . strtolower(str_replace('_', '', $suffix)) . '_',
            'apps' => $apps,
        ];
    }

    private function runTarget(array $target): array
    {
        $session = $this->createAdminSession($target);
        $steps = [];
        $steps['listBefore'] = $this->normalizeAppList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/list',
            ['page' => 1, 'limit' => 100]
        )), $target);
        $steps['singleDisable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/status',
            ['app_code' => $target['apps']['single']['code'], 'status' => 0]
        ));
        $steps['singleAfterDisable'] = $this->appStatusFact($target['apps']['single']['id']);
        $steps['singleEnable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/status',
            ['app_code' => $target['apps']['single']['code'], 'status' => 1]
        ));
        $steps['singleAfterEnable'] = $this->appStatusFact($target['apps']['single']['id']);
        $steps['singleMissing'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/status',
            ['app_code' => self::PREFIX . 'MISSING', 'status' => 0]
        ));
        $steps['singleInvalidStatus'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/status',
            ['app_code' => $target['apps']['single']['code'], 'status' => 2]
        ));
        $steps['batchDisable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/batch-status',
            [
                'app_ids' => [$target['apps']['batchOne']['id'], $target['apps']['batchTwo']['id']],
                'status' => 0,
            ]
        ));
        $steps['batchAfterDisable'] = $this->appStatusFacts([
            $target['apps']['batchOne']['id'],
            $target['apps']['batchTwo']['id'],
        ]);
        $steps['batchEnableDuplicateIds'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/batch-status',
            [
                'app_ids' => [$target['apps']['batchOne']['id'], $target['apps']['batchOne']['id'], $target['apps']['batchTwo']['id']],
                'status' => 1,
            ]
        ));
        $steps['batchAfterEnable'] = $this->appStatusFacts([
            $target['apps']['batchOne']['id'],
            $target['apps']['batchTwo']['id'],
        ]);
        $steps['batchEmptyIds'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/batch-status',
            ['app_ids' => [], 'status' => 1]
        ));
        $steps['batchMissingApp'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/batch-status',
            ['app_ids' => [$target['apps']['batchOne']['id'], 999999999999], 'status' => 1]
        ));
        $steps['deleteDependencyBefore'] = $this->deleteDependencyFacts([
            $target['apps']['deleteOne']['id'],
            $target['apps']['deleteTwo']['id'],
        ]);
        $steps['deleteApps'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/delete',
            [
                'app_ids' => [$target['apps']['deleteOne']['id'], $target['apps']['deleteOne']['id'], $target['apps']['deleteTwo']['id']],
            ]
        ));
        $steps['deleteDependencyAfter'] = $this->deleteDependencyFacts([
            $target['apps']['deleteOne']['id'],
            $target['apps']['deleteTwo']['id'],
        ]);
        $steps['deleteAgainMissing'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/delete',
            ['app_ids' => [$target['apps']['deleteOne']['id']]]
        ));
        $steps['listAfterDelete'] = $this->normalizeAppList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/list',
            ['page' => 1, 'limit' => 100]
        )), $target);
        return $steps;
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

    private function normalizeAppList(array $data, array $target): array
    {
        $apps = array_values(array_filter($data['apps'] ?? [], function (array $app) use ($target): bool {
            return str_starts_with((string)($app['app_code'] ?? ''), $target['labelPrefix']);
        }));
        return array_map(function (array $app) use ($target): array {
            return [
                'id' => $this->dynamicId($app['id'] ?? 0),
                'app_code' => $this->normalizeTargetText((string)($app['app_code'] ?? ''), $target),
                'api_token_state' => trim((string)($app['api_token'] ?? '')) === '' ? 'empty' : 'present',
                'name' => $this->normalizeTargetText((string)($app['name'] ?? ''), $target),
                'status' => (int)($app['status'] ?? -1),
                'max_devices' => (int)($app['max_devices'] ?? -1),
                'heartbeat_interval' => (int)($app['heartbeat_interval'] ?? -1),
                'heartbeat_enabled' => (int)($app['heartbeat_enabled'] ?? -1),
                'verification_enabled' => (int)($app['verification_enabled'] ?? -1),
                'device_binding_enabled' => (int)($app['device_binding_enabled'] ?? -1),
                'shared_cards_enabled' => (int)($app['shared_cards_enabled'] ?? -1),
                'login_ip_binding_enabled' => (int)($app['login_ip_binding_enabled'] ?? -1),
                'web_card_query_enabled' => (int)($app['web_card_query_enabled'] ?? -1),
                'unbind_interval_seconds' => (int)($app['unbind_interval_seconds'] ?? -1),
                'unbind_deduct_seconds' => (int)($app['unbind_deduct_seconds'] ?? -1),
                'unbind_deduct_uses' => (int)($app['unbind_deduct_uses'] ?? -1),
                'api_success_code' => (int)($app['api_success_code'] ?? -1),
                'api_routes_keys' => $this->sortedKeys(is_array($app['api_routes'] ?? null) ? $app['api_routes'] : []),
                'latest_version' => (string)($app['latest_version'] ?? ''),
                'client_auth_mode' => (string)($app['client_auth_mode'] ?? ''),
                'client_crypto_alg' => (string)($app['client_crypto_alg'] ?? ''),
                'remark' => $this->normalizeTargetText((string)($app['remark'] ?? ''), $target),
                'created_at' => $this->dateState($app['created_at'] ?? ''),
                'updated_at' => $this->dateState($app['updated_at'] ?? ''),
                'cards_total' => (int)($app['cards_total'] ?? -1),
                'devices_total' => (int)($app['devices_total'] ?? -1),
                'sessions_active' => (int)($app['sessions_active'] ?? -1),
            ];
        }, $apps);
    }

    private function normalizeError(array $step): array
    {
        $body = is_array($step['body'] ?? null) ? $step['body'] : [];
        return [
            'httpStatus' => (int)($step['httpStatus'] ?? 0),
            'code' => (int)($body['code'] ?? 0),
            'error' => (string)($body['error'] ?? ''),
            'message_state' => trim((string)($body['message'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function appStatusFact(int $appId): array
    {
        $row = $this->database->selectRowV2('SELECT `status` FROM `auth_apps` WHERE `id` = ?', [$appId]);
        return is_array($row)
            ? ['exists' => true, 'status' => (int)($row['status'] ?? -1)]
            : ['exists' => false];
    }

    private function appStatusFacts(array $appIds): array
    {
        return array_map(fn(int $appId): array => $this->appStatusFact($appId), $appIds);
    }

    private function deleteDependencyFacts(array $appIds): array
    {
        $facts = [];
        foreach ($appIds as $appId) {
            $facts[] = [
                'app' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_apps` WHERE `id` = ?', [$appId]),
                'accounts' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_accounts` WHERE `app_id` = ?', [$appId]),
                'cards' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_cards` WHERE `app_id` = ?', [$appId]),
                'devices' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_devices` WHERE `app_id` = ?', [$appId]),
                'sessions' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_sessions` WHERE `app_id` = ?', [$appId]),
                'nonces' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_nonces` WHERE `app_id` = ?', [$appId]),
                'login_challenges' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_login_challenges` WHERE `app_id` = ?', [$appId]),
                'remote_configs' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_remote_configs` WHERE `app_id` = ?', [$appId]),
                'security_policies' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_security_policies` WHERE `app_id` = ?', [$appId]),
                'audit_logs' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_audit_logs` WHERE `app_id` = ?', [$appId]),
                'app_secrets' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_app_secrets` WHERE `app_id` = ?', [$appId]),
            ];
        }
        return $facts;
    }

    private function seedDeleteDependencies(array $app): void
    {
        $appId = $app['id'];
        $accountId = (int)$this->exec(
            'INSERT INTO `auth_accounts` (`app_id`, `username`, `password_hash`, `status`, `expires_at`, `max_devices`) VALUES (?, ?, ?, ?, ?, ?)',
            [$appId, $app['code'] . '_account', password_hash('password', PASSWORD_BCRYPT), 1, '2030-01-01 00:00:00', 3]
        );
        $cardId = (int)$this->exec(
            'INSERT INTO `auth_cards` (`app_id`, `card_hash`, `card_cipher`, `card_fingerprint`, `card_type`, `duration_seconds`, `max_devices`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, $this->seedHash($app, 'card'), Crypto::encryptSecret($app['code'] . '_card', $this->systemKey), 'CARD...LIFE', 'time', 3600, 3, 0]
        );
        $deviceId = (int)$this->exec(
            'INSERT INTO `auth_devices` (`app_id`, `account_id`, `card_id`, `card_hash`, `device_hash`, `device_name`, `install_id`, `device_public_key`, `device_key_alg`, `machine_profile_hash`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, $accountId, $cardId, $this->seedHash($app, 'card'), $this->seedHash($app, 'device'), $app['code'] . '_device', $app['code'] . '_install', '', 'local_key_v1', $this->seedHash($app, 'machine'), 1]
        );
        $sessionId = (int)$this->exec(
            'INSERT INTO `auth_sessions` (`app_id`, `account_id`, `device_id`, `card_id`, `card_hash`, `card_fingerprint`, `token_hash`, `proof_mode`, `status`, `ip`, `expires_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, $accountId, $deviceId, $cardId, $this->seedHash($app, 'card'), 'CARD...LIFE', $this->seedHash($app, 'session'), 'local_key_v1', 1, '127.0.0.1', '2030-01-01 00:00:00']
        );
        $this->exec('INSERT INTO `auth_nonces` (`app_id`, `nonce_hash`, `expires_at`) VALUES (?, ?, ?)', [$appId, $this->seedHash($app, 'nonce'), '2030-01-01 00:00:00']);
        $this->exec('INSERT INTO `auth_login_challenges` (`app_id`, `install_id`, `challenge_id`, `server_nonce`, `expires_at`) VALUES (?, ?, ?, ?, ?)', [$appId, $app['code'] . '_install_challenge', $app['code'] . '_challenge', 'server_nonce', '2030-01-01 00:00:00']);
        $this->exec('INSERT INTO `auth_remote_configs` (`app_id`, `notice`, `config_json`, `variables_json`, `version`, `force_update`, `download_url`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [$appId, 'notice', '{}', '{}', '1.0.0', 0, '', 1]);
        $this->exec('INSERT INTO `auth_security_policies` (`app_id`, `trusted_event_types_json`, `updated_by`) VALUES (?, ?, ?)', [$appId, '{}', self::PREFIX . 'tester']);
        $this->exec('INSERT INTO `auth_audit_logs` (`app_id`, `account_id`, `action`, `message`, `ip`) VALUES (?, ?, ?, ?, ?)', [$appId, $accountId, 'app_lifecycle_seed', $app['code'] . '_audit', '127.0.0.1']);
        $this->exec('INSERT INTO `auth_app_secrets` (`app_id`, `secret_cipher`, `secret_fingerprint`, `status`) VALUES (?, ?, ?, ?)', [$appId, Crypto::encryptSecret($app['code'] . '_secret', $this->systemKey), $this->seedHash($app, 'secret'), 1]);
        if ($sessionId <= 0) {
            throw new RuntimeException('session seed failed');
        }
    }

    private function createAdminSession(array $target): array
    {
        $username = $target['usernamePrefix'] . 'admin';
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity App Lifecycle', $target['baseUrl']]
        );
        $token = Crypto::token();
        $keyText = Crypto::encodeBase64Url(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', time() + 3600);
        $this->exec(
            'INSERT INTO `auth_admin_sessions` (`token_hash`, `key_cipher`, `ip`, `admin_username`, `expires_at`, `status`) VALUES (?, ?, ?, ?, ?, ?)',
            [Crypto::sha256($token), Crypto::encryptSecret($keyText, $this->systemKey), '127.0.0.1', $username, $expiresAt, 1]
        );
        return [
            'token' => $token,
            'rawKey' => Crypto::decodeBase64Url($keyText),
        ];
    }

    private function insertApp(string $appCode, string $name): array
    {
        $id = (int)$this->exec(
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
                $appCode . '_remark',
            ]
        );
        return ['id' => $id, 'code' => $appCode];
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
        $apps = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . '%']);
        foreach ($apps as $app) {
            $this->deleteAppRows((int)$app['id']);
        }
        $this->exec('DELETE FROM `sub_admin` WHERE `username` LIKE ?', ['al%']);
    }

    private function deleteAdminSessions(): void
    {
        if ($this->tableExists('auth_admin_nonces')) {
            $sessions = $this->database->selectV2('SELECT `id` FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', ['al%']);
            foreach ($sessions as $session) {
                $this->exec('DELETE FROM `auth_admin_nonces` WHERE `session_id` = ?', [(int)$session['id']]);
            }
        }
        $this->exec('DELETE FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', ['al%']);
    }

    private function deleteAppRows(int $appId): void
    {
        $tables = [
            'auth_sessions',
            'auth_login_challenges',
            'auth_nonces',
            'auth_devices',
            'auth_cards',
            'auth_accounts',
            'auth_remote_variable_apps',
            'auth_remote_configs',
            'auth_message_actions',
            'auth_messages',
            'auth_security_reports',
            'auth_security_policies',
            'auth_audit_logs',
            'auth_app_secrets',
        ];
        foreach ($tables as $table) {
            if (!$this->tableExists($table)) {
                continue;
            }
            $this->exec("DELETE FROM `{$table}` WHERE `app_id` = ?", [$appId]);
        }
        $this->exec('DELETE FROM `auth_apps` WHERE `id` = ?', [$appId]);
    }

    private function tableExists(string $table): bool
    {
        $row = $this->database->selectRowV2(
            'SELECT COUNT(*) AS `c` FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            [$table]
        );
        return (int)($row['c'] ?? 0) > 0;
    }

    private function countRows(string $sql, array $params): int
    {
        $row = $this->database->selectRowV2($sql, $params);
        return (int)($row['c'] ?? 0);
    }

    private function exec(string $sql, array $params = []): int|string
    {
        return $this->database->exec($sql, $params);
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

    private function normalizeTargetText(string $value, array $target): string
    {
        return str_replace($target['labelPrefix'], '<target>_', $value);
    }

    private function dateState(mixed $value): string
    {
        return trim((string)$value) === '' ? 'empty' : 'present';
    }

    private function dynamicId(mixed $value): array
    {
        $id = (int)$value;
        return ['type' => 'id', 'present' => $id > 0];
    }

    private function sortedKeys(array $row): array
    {
        $keys = array_map('strval', array_keys($row));
        sort($keys);
        return $keys;
    }

    private function seedHash(array $app, string $label): string
    {
        return hash('sha256', $app['code'] . '_' . $label);
    }

    private function diff(mixed $left, mixed $right, string $path): array
    {
        if (is_array($left) && is_array($right)) {
            $diffs = [];
            $keys = array_unique(array_merge(array_keys($left), array_keys($right)));
            sort($keys);
            foreach ($keys as $key) {
                if (!array_key_exists($key, $left)) {
                    $diffs[] = $path . '.' . $key . ' missing on left';
                    continue;
                }
                if (!array_key_exists($key, $right)) {
                    $diffs[] = $path . '.' . $key . ' missing on right';
                    continue;
                }
                array_push($diffs, ...$this->diff($left[$key], $right[$key], $path . '.' . $key));
            }
            return $diffs;
        }
        return $left === $right ? [] : [$path . ' expected ' . $this->json($left) . ' got ' . $this->json($right)];
    }

    private function printResult(string $name, array $result): void
    {
        echo strtoupper($name) . " " . $this->json($result) . "\n";
    }

    private function json(mixed $value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            throw new RuntimeException('json encode failed');
        }
        return $json;
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

$check = new AdminAppLifecycleParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
