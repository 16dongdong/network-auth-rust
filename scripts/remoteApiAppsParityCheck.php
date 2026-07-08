<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class RemoteApiAppsParityCheck
{
    private const PREFIX = 'E2E_RAPP_';

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
            echo "CLEANED remote api apps fixtures\n";
            return 0;
        }

        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl));
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl));
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'remoteApiApps');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK remote api apps\n";
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
        $createdAppCode = self::PREFIX . 'CREATED_' . $suffix;
        $deleteAppCode = self::PREFIX . 'DELETE_' . $suffix;
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => $appCode,
            'createdAppCode' => $createdAppCode,
            'createdAppId' => 0,
            'deleteAppCode' => $deleteAppCode,
            'appId' => $this->insertApp($appCode, 'Remote API Apps Main'),
            'deleteAppId' => $this->insertApp($deleteAppCode, 'Remote API Apps Delete'),
            'tokenName' => self::PREFIX . 'TOKEN_' . $suffix,
        ];
    }

    private function runTarget(array $target): array
    {
        $secret = Crypto::token(32);
        $accessKey = Crypto::token(24);
        $tokenId = $this->insertRemoteApiToken($target['tokenName'], $accessKey, $secret);
        $steps = [];

        $createdApp = $this->successData($this->remoteRequest(
            $target,
            '/remote/apps/create',
            [
                'app_code' => $target['createdAppCode'],
                'name' => $target['name'] . ' remote created',
                'heartbeat_interval' => 444,
                'heartbeat_enabled' => '0',
                'verification_enabled' => 1,
                'device_binding_enabled' => true,
                'shared_cards_enabled' => 1,
                'latest_version' => '2.3.4',
                'client_crypto_alg' => 'rsa_oaep_aes_256_gcm',
                'remark' => 'remote apps create parity',
            ],
            $accessKey,
            $secret
        ));
        $target['createdAppId'] = (int)($createdApp['app_id'] ?? 0);
        $steps['createByCode'] = $this->normalizeCreatedApp($createdApp, $target);
        $steps['createdAppRaw'] = $this->appSettingsRawFact($target['createdAppId']);
        $steps['listAfterCreate'] = $this->normalizeAppList($this->successData($this->remoteRequest(
            $target,
            '/remote/apps/list',
            ['page' => 1, 'limit' => 100],
            $accessKey,
            $secret
        )), $target);
        $steps['apiGetByCode'] = $this->normalizeApiGet($this->successData($this->remoteRequest(
            $target,
            '/remote/apps/api/get',
            ['app_code' => $target['appCode']],
            $accessKey,
            $secret
        )), $target);
        $steps['apiGetById'] = $this->normalizeApiGet($this->successData($this->remoteRequest(
            $target,
            '/remote/apps/api/get',
            ['app_id' => $target['appId']],
            $accessKey,
            $secret
        )), $target);
        $steps['updateApiByCode'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/apps/api/update',
            [
                'app_code' => $target['appCode'],
                'login_ip_binding_enabled' => 1,
                'web_card_query_enabled' => true,
                'unbind_interval_seconds' => 66,
                'unbind_deduct_seconds' => 7,
                'unbind_deduct_uses' => 2,
                'api_success_code' => 299,
                'api_routes' => [
                    ['route' => '/login', 'enabled' => 0, 'call_id' => 'loginCall'],
                    ['route' => '/heartbeat', 'enabled' => 1, 'call_id' => 'heartCall'],
                ],
            ],
            $accessKey,
            $secret
        ));
        $steps['apiRawAfterUpdate'] = $this->appApiRawFact($target['appId']);
        $steps['updateAppByCode'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/apps/update',
            [
                'app_code' => $target['appCode'],
                'name' => $target['name'] . ' remote renamed',
                'heartbeat_interval' => 333,
                'heartbeat_enabled' => 0,
                'verification_enabled' => 1,
                'device_binding_enabled' => 0,
                'shared_cards_enabled' => 1,
                'latest_version' => '9.8.7',
                'client_crypto_alg' => 'rsa_oaep_aes_256_gcm',
                'remark' => 'remote apps parity remark',
            ],
            $accessKey,
            $secret
        ));
        $steps['appRawAfterUpdate'] = $this->appSettingsRawFact($target['appId']);
        $steps['disableById'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/apps/status',
            ['app_id' => $target['appId'], 'status' => 0],
            $accessKey,
            $secret
        ));
        $steps['statusAfterDisable'] = $this->appStatusFact($target['appId']);
        $steps['enableByCode'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/apps/status',
            ['app_code' => $target['appCode'], 'status' => 1],
            $accessKey,
            $secret
        ));
        $steps['statusAfterEnable'] = $this->appStatusFact($target['appId']);
        $steps['keypairById'] = $this->normalizeKeypair($this->successData($this->remoteRequest(
            $target,
            '/remote/apps/generate-keypair',
            ['app_id' => $target['appId'], 'client_crypto_alg' => 'rsa_oaep_aes_256_gcm'],
            $accessKey,
            $secret
        )), $target);
        $steps['deleteByCodes'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/apps/delete',
            ['app_codes' => [$target['deleteAppCode'], $target['deleteAppCode']]],
            $accessKey,
            $secret
        ));
        $steps['deleteAppExistsAfterDelete'] = $this->appExistsFact($target['deleteAppId']);
        $steps['missingApiAppError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/apps/api/get',
            ['app_code' => self::PREFIX . 'MISSING_' . $target['name']],
            $accessKey,
            $secret
        ));
        $steps['invalidAppCodesError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/apps/delete',
            ['app_codes' => 'not-array'],
            $accessKey,
            $secret
        ));
        $steps['invalidCreateCodeError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/apps/create',
            ['app_code' => 'bad app code', 'name' => 'invalid create'],
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

    private function normalizeCreatedApp(array $data, array $target): array
    {
        return [
            'app_id' => $this->targetAppId($data['app_id'] ?? null, $target),
            'app_code' => $this->normalizeAppCode((string)($data['app_code'] ?? ''), $target),
            'client_auth_mode' => (string)($data['client_auth_mode'] ?? ''),
            'client_crypto_alg' => (string)($data['client_crypto_alg'] ?? ''),
            'client_public_key_state' => str_starts_with((string)($data['client_public_key'] ?? ''), '-----BEGIN PUBLIC KEY-----') ? 'pem' : 'other',
        ];
    }

    private function normalizeAppList(array $data, array $target): array
    {
        $apps = is_array($data['apps'] ?? null) ? $data['apps'] : [];
        $facts = [];
        foreach ($apps as $app) {
            if (!is_array($app)) {
                continue;
            }
            $appCode = (string)($app['app_code'] ?? '');
            if (!in_array($appCode, $this->targetAppCodes($target), true)) {
                continue;
            }
            $facts[] = [
                'id' => $this->targetAppId($app['id'] ?? null, $target),
                'app_code' => $this->normalizeAppCode($appCode, $target),
                'api_token_state' => trim((string)($app['api_token'] ?? '')) === '' ? 'empty' : 'present',
                'name_state' => str_contains((string)($app['name'] ?? ''), 'Remote API Apps') || str_contains((string)($app['name'] ?? ''), 'remote created') ? 'expected' : 'other',
                'status' => (int)($app['status'] ?? -1),
                'max_devices' => (int)($app['max_devices'] ?? -1),
                'heartbeat_interval' => (int)($app['heartbeat_interval'] ?? -1),
                'heartbeat_enabled' => (int)($app['heartbeat_enabled'] ?? -1),
                'verification_enabled' => (int)($app['verification_enabled'] ?? -1),
                'device_binding_enabled' => (int)($app['device_binding_enabled'] ?? -1),
                'shared_cards_enabled' => (int)($app['shared_cards_enabled'] ?? -1),
                'latest_version' => (string)($app['latest_version'] ?? ''),
                'client_auth_mode' => (string)($app['client_auth_mode'] ?? ''),
                'client_crypto_alg' => (string)($app['client_crypto_alg'] ?? ''),
                'route_count' => count(is_array($app['api_routes'] ?? null) ? $app['api_routes'] : []),
                'created_at_state' => trim((string)($app['created_at'] ?? '')) === '' ? 'empty' : 'present',
                'updated_at_state' => trim((string)($app['updated_at'] ?? '')) === '' ? 'empty' : 'present',
                'cards_total' => (int)($app['cards_total'] ?? -1),
                'devices_total' => (int)($app['devices_total'] ?? -1),
                'sessions_active' => (int)($app['sessions_active'] ?? -1),
            ];
        }
        usort($facts, static fn(array $left, array $right): int => $left['app_code'] <=> $right['app_code']);
        return $facts;
    }

    private function successData(array $response): array
    {
        $body = is_array($response['body'] ?? null) ? $response['body'] : [];
        if ((int)($response['httpStatus'] ?? 0) !== 200 || (int)($body['code'] ?? -1) !== 0 || !is_array($body['data'] ?? null)) {
            throw new RuntimeException('unexpected success response: ' . $this->json($response));
        }
        return $body['data'];
    }

    private function normalizeApiGet(array $data, array $target): array
    {
        $api = is_array($data['api'] ?? null) ? $data['api'] : [];
        return [
            'app_id' => $this->targetAppId($api['app_id'] ?? null),
            'app_code' => $this->normalizeAppCode((string)($api['app_code'] ?? ''), $target),
            'api_token_state' => trim((string)($api['api_token'] ?? '')) === '' ? 'empty' : 'present',
            'login_ip_binding_enabled' => (int)($api['login_ip_binding_enabled'] ?? -1),
            'web_card_query_enabled' => (int)($api['web_card_query_enabled'] ?? -1),
            'unbind_interval_seconds' => (int)($api['unbind_interval_seconds'] ?? -1),
            'unbind_deduct_seconds' => (int)($api['unbind_deduct_seconds'] ?? -1),
            'unbind_deduct_uses' => (int)($api['unbind_deduct_uses'] ?? -1),
            'api_success_code' => (int)($api['api_success_code'] ?? -1),
            'route_count' => count(is_array($api['api_routes'] ?? null) ? $api['api_routes'] : []),
        ];
    }

    private function normalizeKeypair(array $data, array $target): array
    {
        return [
            'app_code' => $this->normalizeAppCode((string)($data['app_code'] ?? ''), $target),
            'client_crypto_alg' => (string)($data['client_crypto_alg'] ?? ''),
            'client_public_key_state' => str_starts_with((string)($data['client_public_key'] ?? ''), '-----BEGIN PUBLIC KEY-----') ? 'pem' : 'other',
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

    private function appApiRawFact(int $appId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json` FROM `auth_apps` WHERE `id` = ?',
            [$appId]
        );
        $routes = json_decode((string)($row['api_config_json'] ?? '[]'), true);
        return [
            'login_ip_binding_enabled' => (int)($row['login_ip_binding_enabled'] ?? -1),
            'web_card_query_enabled' => (int)($row['web_card_query_enabled'] ?? -1),
            'unbind_interval_seconds' => (int)($row['unbind_interval_seconds'] ?? -1),
            'unbind_deduct_seconds' => (int)($row['unbind_deduct_seconds'] ?? -1),
            'unbind_deduct_uses' => (int)($row['unbind_deduct_uses'] ?? -1),
            'api_success_code' => (int)($row['api_success_code'] ?? -1),
            'login_route' => $this->routeFact(is_array($routes) ? $routes : [], '/login'),
            'heartbeat_route' => $this->routeFact(is_array($routes) ? $routes : [], '/heartbeat'),
        ];
    }

    private function appSettingsRawFact(int $appId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `name`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `latest_version`, `client_crypto_alg`, `remark` FROM `auth_apps` WHERE `id` = ?',
            [$appId]
        );
        return [
            'name_state' => str_contains((string)($row['name'] ?? ''), 'remote renamed') ? 'renamed' : 'other',
            'heartbeat_interval' => (int)($row['heartbeat_interval'] ?? -1),
            'heartbeat_enabled' => (int)($row['heartbeat_enabled'] ?? -1),
            'verification_enabled' => (int)($row['verification_enabled'] ?? -1),
            'device_binding_enabled' => (int)($row['device_binding_enabled'] ?? -1),
            'shared_cards_enabled' => (int)($row['shared_cards_enabled'] ?? -1),
            'latest_version' => (string)($row['latest_version'] ?? ''),
            'client_crypto_alg' => (string)($row['client_crypto_alg'] ?? ''),
            'remark' => (string)($row['remark'] ?? ''),
        ];
    }

    private function routeFact(array $routes, string $route): array
    {
        foreach ($routes as $row) {
            if (is_array($row) && (string)($row['route'] ?? '') === $route) {
                return [
                    'enabled' => (int)($row['enabled'] ?? -1),
                    'call_id' => (string)($row['call_id'] ?? ''),
                ];
            }
        }
        return ['enabled' => -1, 'call_id' => ''];
    }

    private function appStatusFact(int $appId): array
    {
        $row = $this->database->selectRowV2('SELECT `status` FROM `auth_apps` WHERE `id` = ?', [$appId]);
        return ['status' => (int)($row['status'] ?? -1)];
    }

    private function appExistsFact(int $appId): array
    {
        $row = $this->database->selectRowV2('SELECT COUNT(*) AS `count` FROM `auth_apps` WHERE `id` = ?', [$appId]);
        return ['exists' => (int)($row['count'] ?? 0) > 0];
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
            'SELECT `app_id`, `action`, `message`, `ip` FROM `auth_audit_logs` WHERE `action` IN (?, ?, ?, ?) AND `message` LIKE ? ORDER BY `id` ASC',
            [
                'remote_api_update',
                'remote_apps_status',
                'remote_keypair_rotate',
                'remote_apps_delete',
                '%Token：' . $target['tokenName'] . '%',
            ]
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
                $this->json(ClientApiConfig::defaults()),
                '1.0.0',
                'local_key_v1',
                'rsa_oaep_aes_256_gcm',
                '',
                '',
                'remote api apps parity',
            ]
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
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ? OR `app_code` LIKE ? OR `app_code` LIKE ?', [self::PREFIX . 'APP_%', self::PREFIX . 'CREATED_%', self::PREFIX . 'DELETE_%']);
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
            return '<mainApp>';
        }
        if ($target !== null && $id === (int)($target['createdAppId'] ?? 0)) {
            return '<createdApp>';
        }
        if ($target !== null && $id === (int)$target['deleteAppId']) {
            return '<deleteApp>';
        }
        return '<app>';
    }

    private function normalizeAppCode(string $appCode, array $target): string
    {
        return match ($appCode) {
            $target['appCode'] => '<mainApp>',
            $target['createdAppCode'] => '<createdApp>',
            $target['deleteAppCode'] => '<deleteApp>',
            default => $appCode,
        };
    }

    private function targetAppCodes(array $target): array
    {
        return [$target['appCode'], $target['createdAppCode'], $target['deleteAppCode']];
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

$check = new RemoteApiAppsParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
