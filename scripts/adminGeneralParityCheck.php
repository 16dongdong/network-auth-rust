<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class AdminGeneralParityCheck
{
    private const PREFIX = 'E2E_ADMIN_GENERAL_';
    private const ADMIN_PASSWORD = 'AdminGeneral123!';

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
        $siteSnapshot = $this->siteSnapshot();
        $legacyAdminSnapshot = $this->legacyAdminSnapshot();
        $this->cleanup();
        try {
            $targets = [
                'php' => $this->createTarget('php', $this->phpBaseUrl),
                'rust' => $this->createTarget('rust', $this->rustBaseUrl),
            ];
            $results = [];
            foreach ($targets as $name => $target) {
                $this->restoreSiteSnapshot($siteSnapshot, $legacyAdminSnapshot);
                $results[$name] = $this->runTarget($target);
            }
            $this->printResult('php', $results['php']);
            $this->printResult('rust', $results['rust']);
            $diffs = $this->diff($results['php'], $results['rust'], 'adminGeneral');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK admin general\n";
            return 0;
        } finally {
            $this->restoreSiteSnapshot($siteSnapshot, $legacyAdminSnapshot);
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $suffix = strtoupper(substr($name, 0, 3)) . '_' . strtoupper($this->randomAlpha(6));
        $appCode = self::PREFIX . 'APP_' . $suffix;
        $appId = $this->insertApp($appCode);
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => $appCode,
            'appId' => $appId,
            'labelPrefix' => self::PREFIX . $suffix . '_',
            'usernamePrefix' => 'ag' . strtolower(str_replace('_', '', $suffix)) . '_',
        ];
    }

    private function runTarget(array $target): array
    {
        $session = $this->createAdminSession($target);
        $fixtures = $this->seedFixtures($target);
        $steps = [];
        $steps['overview'] = $this->normalizeOverview($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/overview',
            ['app_code' => $target['appCode']]
        )), $target);
        $steps['overviewAll'] = $this->normalizeOverviewAll($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/overview',
            ['_noop' => true]
        )));
        $steps['profileGet'] = $this->normalizeProfile($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/profile/get',
            ['_noop' => true]
        )), $target);
        $steps['profileClearRemember'] = $this->normalizeProfile($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/profile/clear-remember',
            ['_noop' => true]
        )), $target);
        $steps['siteUpdate'] = $this->normalizeSite($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/site/update',
            [
                'hostname' => $target['labelPrefix'] . '系统',
                'site_subtitle' => $target['labelPrefix'] . '管理台',
                'siteurl' => $target['baseUrl'] . '/admin/login/',
                'logo_url' => $target['baseUrl'] . '/assets/logo.png',
                'announcement' => $target['labelPrefix'] . '公告',
                'contact' => $target['labelPrefix'] . '客服',
                'footer_text' => $target['labelPrefix'] . '页脚',
                'custom_json' => '{"theme":"dark","level":2}',
            ]
        )), $target);
        $steps['siteGetAfterUpdate'] = $this->normalizeSite($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/site/get',
            ['_noop' => true]
        )), $target);
        $steps['siteAuditFact'] = $this->siteAuditFact($target);
        $steps['legacySiteFact'] = $this->legacySiteFact($target);
        $steps['invalidHostname'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/site/update',
            ['hostname' => '', 'custom_json' => []]
        ));
        $steps['invalidCustomJson'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/site/update',
            ['hostname' => 'valid', 'custom_json' => '{"broken"']
        ));
        $steps['accountsListBefore'] = $this->normalizeAccounts($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/accounts/list',
            ['app_code' => $target['appCode'], 'page' => 1, 'limit' => 10]
        )), $target);
        $steps['accountDisable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/accounts/status',
            ['account_id' => $fixtures['accountId'], 'status' => 0]
        ));
        $steps['accountEnable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/accounts/status',
            ['account_id' => $fixtures['accountId'], 'status' => 1]
        ));
        $steps['accountExtend'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/accounts/extend',
            ['account_id' => $fixtures['accountId'], 'duration_seconds' => 3600]
        ));
        $steps['accountExtendMissing'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/accounts/extend',
            ['account_id' => 999999999999, 'duration_seconds' => 3600]
        ));
        $steps['devicesListAll'] = $this->normalizeDevices($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/devices/list',
            ['app_code' => $target['appCode'], 'page' => 1, 'limit' => 10]
        )), $target);
        $steps['devicesListByAccount'] = $this->normalizeDevices($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/devices/list',
            ['app_code' => $target['appCode'], 'account_id' => $fixtures['accountId'], 'page' => 1, 'limit' => 10]
        )), $target);
        $steps['deviceDisable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/devices/status',
            ['app_code' => $target['appCode'], 'device_id' => $fixtures['deviceId'], 'status' => 0]
        ));
        $steps['deviceEnable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/devices/status',
            ['app_code' => $target['appCode'], 'device_id' => $fixtures['deviceId'], 'status' => 1]
        ));
        $steps['deviceMissing'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/devices/status',
            ['app_code' => $target['appCode'], 'device_id' => 999999999999, 'status' => 0]
        ));
        $steps['auditsList'] = $this->normalizeAudits($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/audits/list',
            ['app_code' => $target['appCode'], 'page' => 1, 'limit' => 10]
        )), $target);
        $steps['badApp'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/accounts/list',
            ['app_code' => self::PREFIX . 'MISSING', 'page' => 1, 'limit' => 10]
        ));
        $steps['invalidStatus'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/devices/status',
            ['app_code' => $target['appCode'], 'device_id' => $fixtures['deviceId'], 'status' => 2]
        ));
        $steps['profileInvalidPassword'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/profile/update',
            ['current_password' => 'wrong', 'username' => $session['username']]
        ));
        $steps['profileUpdate'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/profile/update',
            [
                'current_password' => self::ADMIN_PASSWORD,
                'username' => $target['usernamePrefix'] . 'admin_next',
            ]
        ));
        $steps['profileUpdate']['username'] = $this->normalizeTargetText((string)$steps['profileUpdate']['username'], $target);
        return $steps;
    }

    private function seedFixtures(array $target): array
    {
        $accountId = (int)$this->exec(
            'INSERT INTO `auth_accounts` (`app_id`, `username`, `password_hash`, `status`, `expires_at`, `max_devices`, `created_at`, `updated_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $target['appId'],
                $target['labelPrefix'] . 'account',
                password_hash('account-password', PASSWORD_BCRYPT),
                1,
                '2030-01-01 00:00:00',
                3,
                '2024-01-01 00:00:00',
                '2024-01-01 00:00:00',
            ]
        );
        $secondAccountId = (int)$this->exec(
            'INSERT INTO `auth_accounts` (`app_id`, `username`, `password_hash`, `status`, `expires_at`, `max_devices`, `created_at`, `updated_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $target['appId'],
                $target['labelPrefix'] . 'account_second',
                password_hash('account-password', PASSWORD_BCRYPT),
                0,
                '2030-02-01 00:00:00',
                2,
                '2024-01-02 00:00:00',
                '2024-01-02 00:00:00',
            ]
        );
        $deviceId = (int)$this->exec(
            'INSERT INTO `auth_devices` (`app_id`, `account_id`, `card_hash`, `device_hash`, `install_id`, `device_public_key`, `device_key_alg`, `machine_profile_hash`, `bind_ip`, `bind_region`, `device_name`, `status`, `first_seen_at`, `last_seen_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $target['appId'],
                $accountId,
                $this->seedHash($target, 'card'),
                $this->seedHash($target, 'device'),
                $target['labelPrefix'] . 'install',
                '',
                'local_key_v1',
                $this->seedHash($target, 'machine'),
                '127.0.0.1',
                'Local',
                $target['labelPrefix'] . 'device',
                1,
                '2024-01-03 00:00:00',
                '2024-01-04 00:00:00',
            ]
        );
        $secondDeviceId = (int)$this->exec(
            'INSERT INTO `auth_devices` (`app_id`, `account_id`, `card_hash`, `device_hash`, `install_id`, `device_public_key`, `device_key_alg`, `machine_profile_hash`, `device_name`, `status`, `first_seen_at`, `last_seen_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $target['appId'],
                $secondAccountId,
                $this->seedHash($target, 'card-second'),
                $this->seedHash($target, 'device-second'),
                $target['labelPrefix'] . 'install_second',
                '',
                'local_key_v1',
                $this->seedHash($target, 'machine-second'),
                $target['labelPrefix'] . 'device_second',
                0,
                '2024-01-05 00:00:00',
                '2024-01-06 00:00:00',
            ]
        );
        $this->exec(
            'INSERT INTO `auth_sessions` (`app_id`, `account_id`, `device_id`, `card_hash`, `card_fingerprint`, `token_hash`, `proof_mode`, `status`, `ip`, `expires_at`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $target['appId'],
                $accountId,
                $deviceId,
                $this->seedHash($target, 'card'),
                'CARD...SEED',
                $this->seedHash($target, 'session'),
                'local_key_v1',
                1,
                '127.0.0.1',
                '2030-01-01 00:00:00',
                '2024-01-07 00:00:00',
            ]
        );
        foreach (['first', 'second'] as $name) {
            $this->exec(
                'INSERT INTO `auth_audit_logs` (`app_id`, `account_id`, `action`, `message`, `ip`, `region`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [
                    $target['appId'],
                    $name === 'first' ? $accountId : null,
                    'general_' . $name,
                    $target['labelPrefix'] . 'audit_' . $name,
                    '127.0.0.1',
                    'Local',
                    $name === 'first' ? '2024-01-08 00:00:00' : '2024-01-09 00:00:00',
                ]
            );
        }
        return [
            'accountId' => $accountId,
            'secondAccountId' => $secondAccountId,
            'deviceId' => $deviceId,
            'secondDeviceId' => $secondDeviceId,
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

    private function normalizeOverview(array $data, array $target): array
    {
        return [
            'app_code' => $data['app_code'] === $target['appCode'] ? '<appCode>' : (string)($data['app_code'] ?? ''),
            'apps_total_state' => ((int)($data['apps_total'] ?? 0)) >= 2 ? 'present' : 'missing',
            'cards_total' => (int)($data['cards_total'] ?? -1),
            'devices_total' => (int)($data['devices_total'] ?? -1),
            'sessions_active' => (int)($data['sessions_active'] ?? -1),
            'card_status' => $data['card_status'] ?? [],
            'device_status' => $data['device_status'] ?? [],
            'single_code_ratio' => $data['single_code_ratio'] ?? [],
            'login_ip_stats' => $data['login_ip_stats'] ?? [],
        ];
    }

    private function normalizeOverviewAll(array $data): array
    {
        return [
            'app_code' => (string)($data['app_code'] ?? ''),
            'apps_total_state' => ((int)($data['apps_total'] ?? 0)) >= 2 ? 'present' : 'missing',
            'cards_total_state' => ((int)($data['cards_total'] ?? 0)) >= 0 ? 'present' : 'missing',
            'devices_total_state' => ((int)($data['devices_total'] ?? 0)) >= 0 ? 'present' : 'missing',
            'sessions_active_state' => ((int)($data['sessions_active'] ?? 0)) >= 0 ? 'present' : 'missing',
            'keys' => $this->sortedKeys($data),
        ];
    }

    private function normalizeProfile(array $data, array $target): array
    {
        $profile = $data['profile'] ?? [];
        return [
            'cleared' => $data['cleared'] ?? null,
            'username' => $this->normalizeTargetText((string)($profile['username'] ?? ''), $target),
            'remember_login_active' => (bool)($profile['remember_login_active'] ?? false),
            'remember_login_expires_at' => $this->dateState($profile['remember_login_expires_at'] ?? ''),
            'session_expires_at' => $this->dateState($profile['session_expires_at'] ?? ''),
            'created_at' => $this->dateState($profile['created_at'] ?? ''),
            'updated_at' => $this->dateState($profile['updated_at'] ?? ''),
        ];
    }

    private function normalizeSite(array $data, array $target): array
    {
        $settings = $data['settings'] ?? [];
        return [
            'saved' => $data['saved'] ?? null,
            'settings' => [
                'hostname' => $this->normalizeTargetText((string)($settings['hostname'] ?? ''), $target),
                'site_subtitle' => $this->normalizeTargetText((string)($settings['site_subtitle'] ?? ''), $target),
                'siteurl_state' => str_contains((string)($settings['siteurl'] ?? ''), '/admin/login/') ? 'login-url' : 'other',
                'logo_url_state' => str_contains((string)($settings['logo_url'] ?? ''), '/assets/logo.png') ? 'logo-url' : 'other',
                'announcement' => $this->normalizeTargetText((string)($settings['announcement'] ?? ''), $target),
                'contact' => $this->normalizeTargetText((string)($settings['contact'] ?? ''), $target),
                'footer_text' => $this->normalizeTargetText((string)($settings['footer_text'] ?? ''), $target),
                'custom_json' => $settings['custom_json'] ?? null,
            ],
        ];
    }

    private function normalizeAccounts(array $data, array $target): array
    {
        $accounts = $data['accounts'] ?? [];
        return array_map(function (array $account) use ($target): array {
            return [
                'id' => $this->dynamicId($account['id'] ?? 0),
                'app_id' => $this->dynamicId($account['app_id'] ?? 0),
                'username' => $this->normalizeTargetText((string)($account['username'] ?? ''), $target),
                'status' => (int)($account['status'] ?? -1),
                'expires_at' => (string)($account['expires_at'] ?? ''),
                'max_devices' => (int)($account['max_devices'] ?? -1),
                'created_at' => $this->dateState($account['created_at'] ?? ''),
                'updated_at' => $this->dateState($account['updated_at'] ?? ''),
            ];
        }, $accounts);
    }

    private function normalizeDevices(array $data, array $target): array
    {
        $devices = $data['devices'] ?? [];
        return array_map(function (array $device) use ($target): array {
            return [
                'id' => $this->dynamicId($device['id'] ?? 0),
                'app_id' => $this->dynamicId($device['app_id'] ?? 0),
                'account_id' => $this->dynamicId($device['account_id'] ?? 0),
            'card_id' => (int)($device['card_id'] ?? 0),
                'card_fingerprint_state' => str_contains((string)($device['card_fingerprint'] ?? ''), '...') ? 'masked' : 'empty',
                'device_hash_state' => strlen((string)($device['device_hash'] ?? '')) === 64 ? 'sha256' : 'other',
                'device_fingerprint_state' => str_contains((string)($device['device_fingerprint'] ?? ''), '...') ? 'masked' : 'other',
                'install_id' => $this->normalizeTargetText((string)($device['install_id'] ?? ''), $target),
                'machine_profile_hash_state' => strlen((string)($device['machine_profile_hash'] ?? '')) === 64 ? 'sha256' : 'other',
                'bind_ip' => $this->normalizeIp((string)($device['bind_ip'] ?? '')),
                'bind_region' => (string)($device['bind_region'] ?? ''),
                'device_name' => $this->normalizeTargetText((string)($device['device_name'] ?? ''), $target),
                'status' => (int)($device['status'] ?? -1),
                'first_seen_at' => (string)($device['first_seen_at'] ?? ''),
                'last_seen_at' => (string)($device['last_seen_at'] ?? ''),
            ];
        }, $devices);
    }

    private function normalizeAudits(array $data, array $target): array
    {
        $logs = $data['logs'] ?? [];
        return array_map(function (array $log) use ($target): array {
            return [
                'id' => $this->dynamicId($log['id'] ?? 0),
                'app_id' => $this->dynamicId($log['app_id'] ?? 0),
                'account_id_state' => ((int)($log['account_id'] ?? 0)) > 0 ? 'present' : 'empty',
                'action' => (string)($log['action'] ?? ''),
                'message' => $this->normalizeTargetText((string)($log['message'] ?? ''), $target),
                'ip' => $this->normalizeIp((string)($log['ip'] ?? '')),
                'region_state' => trim((string)($log['region'] ?? '')) === '' ? 'empty' : 'present',
                'created_at' => (string)($log['created_at'] ?? ''),
            ];
        }, $logs);
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

    private function siteAuditFact(array $target): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `action`, `message`, `ip` FROM `auth_audit_logs` WHERE `app_id` IS NULL AND `action` = ? AND `message` LIKE ? ORDER BY `id` DESC LIMIT 1',
            ['site_settings_update', '更新站点配置：' . $target['labelPrefix'] . '%']
        );
        if (!is_array($row)) {
            return ['exists' => false];
        }
        return [
            'exists' => true,
            'action' => (string)($row['action'] ?? ''),
            'message' => $this->normalizeTargetText((string)($row['message'] ?? ''), $target),
            'ip' => $this->normalizeIp((string)($row['ip'] ?? '')),
        ];
    }

    private function legacySiteFact(array $target): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `hostname`, `siteurl` FROM `sub_admin` ORDER BY `id` ASC LIMIT 1',
            []
        );
        if (!is_array($row)) {
            return ['exists' => false];
        }
        return [
            'exists' => true,
            'hostname' => $this->normalizeTargetText((string)($row['hostname'] ?? ''), $target),
            'siteurl_state' => str_contains((string)($row['siteurl'] ?? ''), '/admin/login/') ? 'login-url' : 'other',
        ];
    }

    private function createAdminSession(array $target): array
    {
        $username = $target['usernamePrefix'] . 'admin';
        $expiresAt = date('Y-m-d H:i:s', time() + 3600);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`, `remember_login_token_hash`, `remember_login_expires_at`) VALUES (?, ?, ?, ?, ?, ?)',
            [
                $username,
                password_hash(self::ADMIN_PASSWORD, PASSWORD_BCRYPT),
                'Parity Admin General',
                $target['baseUrl'],
                $this->seedHash($target, 'remember'),
                $expiresAt,
            ]
        );
        $token = Crypto::token();
        $keyText = Crypto::encodeBase64Url(random_bytes(32));
        $this->exec(
            'INSERT INTO `auth_admin_sessions` (`token_hash`, `key_cipher`, `ip`, `admin_username`, `expires_at`, `status`) VALUES (?, ?, ?, ?, ?, ?)',
            [Crypto::sha256($token), Crypto::encryptSecret($keyText, $this->systemKey), '127.0.0.1', $username, $expiresAt, 1]
        );
        return [
            'token' => $token,
            'rawKey' => Crypto::decodeBase64Url($keyText),
            'username' => $username,
        ];
    }

    private function insertApp(string $appCode): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appCode,
                ClientApiConfig::generateToken(),
                'Parity Admin General',
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
                'admin general parity',
            ]
        );
    }

    private function siteSnapshot(): ?array
    {
        $row = $this->database->selectRowV2('SELECT * FROM `site_settings` WHERE `id` = 1', []);
        return is_array($row) ? $row : null;
    }

    private function legacyAdminSnapshot(): ?array
    {
        $row = $this->database->selectRowV2(
            'SELECT `id`, `hostname`, `siteurl` FROM `sub_admin` ORDER BY `id` ASC LIMIT 1',
            []
        );
        return is_array($row) ? $row : null;
    }

    private function restoreSiteSnapshot(?array $siteSnapshot, ?array $legacyAdminSnapshot): void
    {
        if ($siteSnapshot === null) {
            $this->exec('DELETE FROM `site_settings` WHERE `id` = 1');
        } else {
            $this->exec(
                'INSERT INTO `site_settings` (`id`, `hostname`, `site_subtitle`, `siteurl`, `logo_url`, `announcement`, `contact`, `footer_text`, `custom_json`) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE `hostname` = VALUES(`hostname`), `site_subtitle` = VALUES(`site_subtitle`), `siteurl` = VALUES(`siteurl`), `logo_url` = VALUES(`logo_url`), `announcement` = VALUES(`announcement`), `contact` = VALUES(`contact`), `footer_text` = VALUES(`footer_text`), `custom_json` = VALUES(`custom_json`)',
                [
                    (string)($siteSnapshot['hostname'] ?? ''),
                    (string)($siteSnapshot['site_subtitle'] ?? ''),
                    (string)($siteSnapshot['siteurl'] ?? ''),
                    (string)($siteSnapshot['logo_url'] ?? ''),
                    (string)($siteSnapshot['announcement'] ?? ''),
                    (string)($siteSnapshot['contact'] ?? ''),
                    (string)($siteSnapshot['footer_text'] ?? ''),
                    (string)($siteSnapshot['custom_json'] ?? '{}'),
                ]
            );
        }
        if ($legacyAdminSnapshot !== null) {
            $this->exec(
                'UPDATE `sub_admin` SET `hostname` = ?, `siteurl` = ? WHERE `id` = ?',
                [
                    (string)($legacyAdminSnapshot['hostname'] ?? ''),
                    (string)($legacyAdminSnapshot['siteurl'] ?? ''),
                    (int)$legacyAdminSnapshot['id'],
                ]
            );
        }
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
        $apps = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . 'APP_%']);
        foreach ($apps as $app) {
            $this->deleteAppRows((int)$app['id']);
        }
        $this->exec('DELETE FROM `auth_audit_logs` WHERE `app_id` IS NULL AND `action` = ? AND `message` LIKE ?', ['site_settings_update', '更新站点配置：' . self::PREFIX . '%']);
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

    private function deleteAppRows(int $appId): void
    {
        $tables = [
            'auth_message_actions',
            'auth_messages',
            'auth_security_reports',
            'auth_sessions',
            'auth_devices',
            'auth_card_search_tokens',
            'auth_cards',
            'auth_audit_logs',
            'auth_accounts',
            'auth_remote_configs',
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
        return str_replace(
            [$target['labelPrefix'], $target['appCode'], $target['baseUrl']],
            ['<target>_', '<appCode>', '<baseUrl>'],
            str_replace($target['usernamePrefix'], '<target>_', $value)
        );
    }

    private function normalizeIp(string $ip): string
    {
        return $ip === '127.0.0.1' || $ip === '::1' ? '<local>' : $ip;
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

    private function seedHash(array $target, string $label): string
    {
        return hash('sha256', $target['labelPrefix'] . $label);
    }

    private function diff(mixed $left, mixed $right, string $path): array
    {
        if (is_int($left) && is_float($right)) {
            return ((float)$left) === $right ? [] : [$path . ' expected ' . $this->json($left) . ' got ' . $this->json($right)];
        }
        if (is_float($left) && is_int($right)) {
            return $left === ((float)$right) ? [] : [$path . ' expected ' . $this->json($left) . ' got ' . $this->json($right)];
        }
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

$check = new AdminGeneralParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
