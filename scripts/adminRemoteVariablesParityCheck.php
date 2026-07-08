<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class AdminRemoteVariablesParityCheck
{
    private const APP_PREFIX = 'E2EVAR_';
    private const VARIABLE_PREFIX = 'e2e.var.';
    private const LUA_PREFIX = 'ace.lua.e2e.';
    private const LUA_SOURCE = "return function(ctx)\n    return ctx.appCode\nend";

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
            echo "CLEANED admin remote variables fixtures\n";
            return 0;
        }
        if (in_array('--browser-fixture', $_SERVER['argv'] ?? [], true)) {
            return $this->runBrowserFixture();
        }
        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $session = $this->createAdminSession();
            $phpTarget = $this->createTarget('php', $this->phpBaseUrl);
            $rustTarget = $this->createTarget('rust', $this->rustBaseUrl);
            $phpResult = $this->runTarget($phpTarget, $session);
            $rustResult = $this->runTarget($rustTarget, $session);
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'adminRemoteVariables');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK admin remote variables\n";
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
        $cookie = $this->createAdminLoginCookie();
        $visibleName = $target['variablePrefix'] . 'visible';
        $luaName = $target['luaPrefix'] . 'gameProbe';
        $badLuaName = $target['luaPrefix'] . 'badStored';
        $this->insertRemoteVariable($visibleName, 'visible value', 'public', 1);
        $this->insertRemoteVariable($luaName, $this->protectedLuaSourceValue(), 'public', 1);
        $this->insertRemoteVariable($badLuaName, 'not-json', 'public', 1);
        echo $this->json([
            'baseUrl' => $this->rustBaseUrl,
            'consoleUrl' => rtrim($this->rustBaseUrl, '/') . '/admin/console/#variables',
            'cookieName' => 'sub_admin_token',
            'cookieValue' => $cookie,
            'visibleName' => $visibleName,
            'luaName' => $luaName,
            'badLuaName' => $badLuaName,
        ]) . "\n";
        return 0;
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $suffix = strtolower($name) . '.' . strtolower($this->randomAlpha(6));
        $primaryAppCode = self::APP_PREFIX . strtoupper($name) . '_PRIMARY_' . strtoupper($this->randomAlpha(6));
        $secondaryAppCode = self::APP_PREFIX . strtoupper($name) . '_SECONDARY_' . strtoupper($this->randomAlpha(6));
        $primaryAppId = $this->insertApp($primaryAppCode, 'Parity Remote Variable Primary');
        $secondaryAppId = $this->insertApp($secondaryAppCode, 'Parity Remote Variable Secondary');
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'primaryAppCode' => $primaryAppCode,
            'secondaryAppCode' => $secondaryAppCode,
            'primaryAppId' => $primaryAppId,
            'secondaryAppId' => $secondaryAppId,
            'variablePrefix' => self::VARIABLE_PREFIX . $suffix . '.',
            'luaPrefix' => self::LUA_PREFIX . $suffix . '.',
        ];
    }

    private function runTarget(array $target, array $session): array
    {
        $steps = [];
        $steps['legacyMoved'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/config/variables/set',
            ['variables' => ['legacy' => 'value']]
        ));
        $steps['emptyList'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $target['variablePrefix']]
        )), $target);

        $publicName = $target['variablePrefix'] . 'public';
        $publicCreate = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $publicName,
                'value' => "enabled\ntrue",
                'scope' => 'public',
                'status' => 1,
            ]
        ));
        $publicId = $this->variableIdFromData($publicCreate);
        $steps['createPublic'] = $this->normalizeSave($publicCreate);
        $steps['duplicatePublic'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $publicName,
                'value' => 'duplicate',
                'scope' => 'public',
                'status' => 1,
            ]
        ));
        $steps['updatePublic'] = $this->normalizeSave($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/update',
            [
                'variable_id' => $publicId,
                'name' => $publicName,
                'value' => 'updated text',
                'scope' => 'public',
                'status' => '0',
            ]
        )));
        $steps['listPublicUpdated'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $publicName]
        )), $target);
        $steps['enablePublic'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/status',
            ['variable_id' => $publicId, 'status' => 1]
        ));

        $privateName = $target['variablePrefix'] . 'private';
        $privateCreate = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $privateName,
                'value' => 'private value',
                'scope' => 'private',
                'status' => true,
                'app_ids' => [$target['primaryAppId'], $target['secondaryAppId'], $target['primaryAppId'], 'bad', 0],
            ]
        ));
        $privateId = $this->variableIdFromData($privateCreate);
        $steps['createPrivate'] = $this->normalizeSave($privateCreate);
        $steps['listPrimaryAppFilter'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $target['variablePrefix'], 'app_id' => $target['primaryAppId']]
        )), $target);
        $steps['listSecondaryAppFilter'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $target['variablePrefix'], 'app_id' => $target['secondaryAppId']]
        )), $target);
        $steps['setPublicAppsError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/variables/apps/set',
            ['variable_id' => $publicId, 'app_ids' => [$target['primaryAppId']]]
        ));
        $steps['setPrivateApps'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/apps/set',
            ['variable_id' => $privateId, 'app_ids' => [$target['secondaryAppId']]]
        ));
        $steps['privateAfterSetApps'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $privateName]
        )), $target);
        $steps['convertPrivateToPublic'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/convert',
            ['variable_id' => $privateId, 'scope' => 'public', 'app_ids' => [$target['primaryAppId']]]
        ));
        $steps['privateAfterPublicConvert'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $privateName]
        )), $target);
        $steps['convertPublicToPrivate'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/convert',
            ['variable_id' => $privateId, 'scope' => 'private', 'app_ids' => [$target['primaryAppId']]]
        ));
        $steps['privateAfterPrivateConvert'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $privateName]
        )), $target);

        $luaName = $target['luaPrefix'] . 'gameProbe';
        $luaCreate = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $luaName,
                'lua_source' => self::LUA_SOURCE,
                'scope' => 'public',
                'status' => 1,
            ]
        ));
        $steps['createLua'] = $this->normalizeSave($luaCreate);
        $steps['luaList'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $target['luaPrefix']]
        )), $target);
        $steps['invalidLuaValue'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $target['luaPrefix'] . 'badCreate',
                'value' => 'return function() return true end',
                'scope' => 'public',
                'status' => 1,
            ]
        ));

        $badLuaName = $target['luaPrefix'] . 'badStored';
        $plainAfterBadName = $target['variablePrefix'] . 'afterBad';
        $this->insertRemoteVariable($badLuaName, 'not-json', 'public', 1);
        $this->insertRemoteVariable($plainAfterBadName, 'still visible', 'public', 1);
        $steps['badLuaIsolationList'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $target['luaPrefix']]
        )), $target);
        $steps['afterBadPlainList'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $plainAfterBadName]
        )), $target);

        $deleteA = $this->variableIdFromData($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $target['variablePrefix'] . 'deleteA',
                'value' => 'delete A',
                'scope' => 'public',
                'status' => 1,
            ]
        )));
        $deleteB = $this->variableIdFromData($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $target['variablePrefix'] . 'deleteB',
                'value' => 'delete B',
                'scope' => 'public',
                'status' => 1,
            ]
        )));
        $steps['batchDisable'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/batch-status',
            ['variable_ids' => [$publicId, $privateId, $privateId], 'status' => 0]
        ));
        $steps['afterBatchDisable'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $target['variablePrefix'], 'status' => '0']
        )), $target);
        $steps['batchDelete'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/batch-delete',
            ['variable_ids' => [$deleteA, $deleteB, $deleteB]]
        ));
        $steps['deletePublic'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/delete',
            ['variable_id' => $publicId]
        ));
        $steps['finalList'] = $this->normalizeList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/variables/list',
            ['keyword' => $target['variablePrefix']]
        )), $target);

        $steps['missingVariableError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/variables/status',
            ['variable_id' => 922337203685477, 'status' => 1]
        ));
        $steps['invalidPrivateAppsError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $target['variablePrefix'] . 'missingApps',
                'value' => 'private',
                'scope' => 'private',
                'status' => 1,
                'app_ids' => [922337203685477],
            ]
        ));
        $steps['invalidScopeError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/variables/create',
            [
                'name' => $target['variablePrefix'] . 'badScope',
                'value' => 'scope',
                'scope' => 'shared',
                'status' => 1,
            ]
        ));
        return ['steps' => $steps];
    }

    private function normalizeList(array $data, array $target): array
    {
        $rows = [];
        foreach (is_array($data['variables'] ?? null) ? $data['variables'] : [] as $row) {
            if (is_array($row)) {
                $rows[] = $this->normalizeVariableRow($row, $target);
            }
        }
        usort($rows, static fn(array $left, array $right): int => strcmp($left['name'], $right['name']));
        return $rows;
    }

    private function normalizeVariableRow(array $row, array $target): array
    {
        $name = (string)($row['name'] ?? '');
        return [
            'id_state' => ((int)($row['id'] ?? 0)) > 0 ? 'present' : 'missing',
            'name' => $this->normalizeVariableName($name, $target),
            'value' => $this->normalizeVariableValue($name, (string)($row['value'] ?? '')),
            'scope' => (string)($row['scope'] ?? ''),
            'status' => (int)($row['status'] ?? -1),
            'app_roles' => $this->normalizeAppRoles($row['app_ids'] ?? [], $target),
            'app_names' => $this->normalizeAppNames($row['app_names'] ?? []),
            'app_count' => (int)($row['app_count'] ?? -1),
            'created_at_state' => trim((string)($row['created_at'] ?? '')) === '' ? 'empty' : 'present',
            'updated_at_state' => trim((string)($row['updated_at'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function normalizeVariableName(string $name, array $target): string
    {
        if (str_starts_with($name, $target['variablePrefix'])) {
            return '<var>.' . substr($name, strlen($target['variablePrefix']));
        }
        if (str_starts_with($name, $target['luaPrefix'])) {
            return 'ace.lua.<lua>.' . substr($name, strlen($target['luaPrefix']));
        }
        return $name;
    }

    private function normalizeVariableValue(string $name, string $value): array
    {
        if (!str_starts_with($name, 'ace.lua.')) {
            return [
                'kind' => 'plain',
                'value' => $value,
            ];
        }
        $payload = json_decode($value, true);
        if (!is_array($payload)) {
            return [
                'kind' => 'invalidLuaStorage',
                'value' => $value,
            ];
        }
        return [
            'kind' => 'luaStorage',
            'format' => (string)($payload['format'] ?? ''),
            'sourceSha256' => (string)($payload['sourceSha256'] ?? ''),
            'ciphertext_state' => trim((string)($payload['ciphertext'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function normalizeAppRoles(mixed $appIds, array $target): array
    {
        $roles = [];
        foreach (is_array($appIds) ? $appIds : [] as $appId) {
            $id = (int)$appId;
            if ($id === (int)$target['primaryAppId']) {
                $roles[] = 'primary';
            } elseif ($id === (int)$target['secondaryAppId']) {
                $roles[] = 'secondary';
            } elseif ($id > 0) {
                $roles[] = 'other';
            }
        }
        sort($roles);
        return array_values(array_unique($roles));
    }

    private function normalizeAppNames(mixed $appNames): array
    {
        $names = array_values(array_filter(array_map(
            static fn(mixed $name): string => (string)$name,
            is_array($appNames) ? $appNames : []
        ), static fn(string $name): bool => $name !== ''));
        sort($names);
        return $names;
    }

    private function normalizeSave(array $data): array
    {
        return [
            'saved' => (bool)($data['saved'] ?? false),
            'variable_id_state' => ((int)($data['variable_id'] ?? 0)) > 0 ? 'present' : 'missing',
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

    private function variableIdFromData(array $data): int
    {
        $variableId = (int)($data['variable_id'] ?? 0);
        if ($variableId <= 0) {
            throw new RuntimeException('missing variable id: ' . $this->json($data));
        }
        return $variableId;
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

    private function createAdminSession(): array
    {
        $username = self::APP_PREFIX . 'admin_' . strtolower($this->randomAlpha(8));
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity Remote Variables Admin', $this->rustBaseUrl]
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

    private function createAdminLoginCookie(): string
    {
        $username = self::APP_PREFIX . 'browser_admin_' . strtolower($this->randomAlpha(6));
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity Remote Variables Browser', $this->rustBaseUrl]
        );
        $session = md5($username . $passwordHash . hash('sha256', $this->systemKey));
        return Crypto::encryptProtectedText($username . "\t" . $session, $this->systemKey);
    }

    private function protectedLuaSourceValue(): string
    {
        return $this->json([
            'format' => 'ace.remoteLua.source.v1',
            'ciphertext' => Crypto::encryptProtectedText(self::LUA_SOURCE, $this->systemKey),
            'sourceSha256' => hash('sha256', self::LUA_SOURCE),
        ]);
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
                'admin remote variables parity',
            ]
        );
    }

    private function insertRemoteVariable(string $name, string $value, string $scope, int $status): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_remote_variables` (`name`, `value`, `scope`, `status`) VALUES (?, ?, ?, ?)',
            [$name, $value, $scope, $status]
        );
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
        $this->deleteRemoteVariables();
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::APP_PREFIX . '%']);
        foreach ($rows as $row) {
            $this->deleteAppRows((int)$row['id']);
        }
        $this->exec('DELETE FROM `sub_admin` WHERE `username` LIKE ?', [self::APP_PREFIX . '%']);
    }

    private function deleteAdminSessions(): void
    {
        if ($this->tableExists('auth_admin_nonces')) {
            $sessions = $this->database->selectV2('SELECT `id` FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', [self::APP_PREFIX . '%']);
            foreach ($sessions as $session) {
                $this->exec('DELETE FROM `auth_admin_nonces` WHERE `session_id` = ?', [(int)$session['id']]);
            }
        }
        $this->exec('DELETE FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', [self::APP_PREFIX . '%']);
    }

    private function deleteRemoteVariables(): void
    {
        $rows = $this->database->selectV2(
            'SELECT `id` FROM `auth_remote_variables` WHERE `name` LIKE ? OR `name` LIKE ?',
            [self::VARIABLE_PREFIX . '%', self::LUA_PREFIX . '%']
        );
        $variableIds = array_values(array_filter(array_map(
            static fn(array $row): int => (int)($row['id'] ?? 0),
            $rows
        ), static fn(int $id): bool => $id > 0));
        if ($variableIds === []) {
            return;
        }
        $placeholders = implode(', ', array_fill(0, count($variableIds), '?'));
        $this->exec("DELETE FROM `auth_remote_variable_apps` WHERE `variable_id` IN ({$placeholders})", $variableIds);
        $this->exec("DELETE FROM `auth_remote_variables` WHERE `id` IN ({$placeholders})", $variableIds);
    }

    private function deleteAppRows(int $appId): void
    {
        if ($this->tableExists('auth_remote_variable_apps')) {
            $this->exec('DELETE FROM `auth_remote_variable_apps` WHERE `app_id` = ?', [$appId]);
        }
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

$check = new AdminRemoteVariablesParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
