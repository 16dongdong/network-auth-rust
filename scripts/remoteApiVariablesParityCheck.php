<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;

final class RemoteApiVariablesParityCheck
{
    private const PREFIX = 'E2E_RVAR_';

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
            echo "CLEANED remote api variable fixtures\n";
            return 0;
        }

        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl));
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl));
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'remoteApiVariables');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK remote api variables\n";
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
        $secondAppCode = self::PREFIX . 'APP2_' . $suffix;
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => $appCode,
            'appId' => $this->insertApp($appCode, 'Remote API Variables Primary'),
            'secondAppCode' => $secondAppCode,
            'secondAppId' => $this->insertApp($secondAppCode, 'Remote API Variables Secondary'),
            'tokenName' => self::PREFIX . 'TOKEN_' . $suffix,
            'plainName' => self::PREFIX . 'plain.' . strtolower($suffix),
            'privateName' => self::PREFIX . 'private.' . strtolower($suffix),
            'luaName' => 'ace.lua.' . self::PREFIX . 'probe.' . strtolower($suffix),
        ];
    }

    private function runTarget(array $target): array
    {
        $secret = Crypto::token(32);
        $accessKey = Crypto::token(24);
        $tokenId = $this->insertRemoteApiToken($target['tokenName'], $accessKey, $secret);
        $steps = [];

        $steps['createPlain'] = $this->normalizeSaved($this->successData($this->remoteRequest(
            $target,
            '/remote/variables/upsert',
            [
                'name' => $target['plainName'],
                'value' => "plain value\nline two",
                'scope' => 'public',
                'status' => 1,
            ],
            $accessKey,
            $secret
        )));
        $steps['updatePlain'] = $this->normalizeSaved($this->successData($this->remoteRequest(
            $target,
            '/remote/variables/upsert',
            [
                'name' => $target['plainName'],
                'value' => 'updated plain value',
                'scope' => 'public',
                'status' => 0,
            ],
            $accessKey,
            $secret
        )));
        $steps['plainRawAfterUpdate'] = $this->variableRawFact($target['plainName'], $target);

        $steps['createPrivateByCodes'] = $this->normalizeSaved($this->successData($this->remoteRequest(
            $target,
            '/remote/variables/upsert',
            [
                'name' => $target['privateName'],
                'value' => 'private value',
                'scope' => 'private',
                'status' => 1,
                'app_codes' => [$target['appCode'], $target['secondAppCode'], $target['appCode']],
            ],
            $accessKey,
            $secret
        )));
        $steps['privateRawAfterCreate'] = $this->variableRawFact($target['privateName'], $target);

        $steps['createLuaSource'] = $this->normalizeSaved($this->successData($this->remoteRequest(
            $target,
            '/remote/variables/upsert',
            [
                'name' => $target['luaName'],
                'lua_source' => "return function(ctx)\n    return ctx.appCode\nend",
                'scope' => 'public',
                'status' => 1,
            ],
            $accessKey,
            $secret
        )));
        $steps['luaRawAfterCreate'] = $this->variableRawFact($target['luaName'], $target);

        $steps['listAll'] = $this->normalizeVariableList($this->successData($this->remoteRequest(
            $target,
            '/remote/variables/list',
            [
                'keyword' => self::PREFIX,
                'scope' => '',
                'status' => '',
                'page' => 1,
                'limit' => 50,
            ],
            $accessKey,
            $secret
        )), $target);
        $steps['listPrivateByApp'] = $this->normalizeVariableList($this->successData($this->remoteRequest(
            $target,
            '/remote/variables/list',
            [
                'keyword' => self::PREFIX,
                'scope' => 'private',
                'status' => 1,
                'app_id' => $target['appId'],
            ],
            $accessKey,
            $secret
        )), $target);

        $steps['statusByNames'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/variables/status',
            ['names' => [$target['plainName'], $target['privateName'], $target['plainName']], 'status' => 1],
            $accessKey,
            $secret
        ));
        $steps['rawAfterStatus'] = $this->selectedVariableFacts($target);

        $steps['publicAppsError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/variables/apps/set',
            ['name' => $target['plainName'], 'app_codes' => [$target['appCode']]],
            $accessKey,
            $secret
        ));
        $steps['setPrivateApps'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/variables/apps/set',
            ['name' => $target['privateName'], 'app_codes' => [$target['secondAppCode']]],
            $accessKey,
            $secret
        ));
        $steps['privateRawAfterAppsSet'] = $this->variableRawFact($target['privateName'], $target);

        $steps['convertPlainPrivate'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/variables/convert',
            ['name' => $target['plainName'], 'scope' => 'private', 'app_codes' => [$target['appCode']]],
            $accessKey,
            $secret
        ));
        $steps['plainRawAfterPrivateConvert'] = $this->variableRawFact($target['plainName'], $target);
        $steps['convertPlainPublic'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/variables/convert',
            ['name' => $target['plainName'], 'scope' => 'public'],
            $accessKey,
            $secret
        ));
        $steps['plainRawAfterPublicConvert'] = $this->variableRawFact($target['plainName'], $target);

        $steps['unknownVariableError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/variables/status',
            ['name' => self::PREFIX . 'missing.' . $target['name'], 'status' => 1],
            $accessKey,
            $secret
        ));
        $steps['invalidAppCodesError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/variables/upsert',
            ['name' => self::PREFIX . 'badcodes.' . $target['name'], 'value' => 'x', 'scope' => 'private', 'app_codes' => []],
            $accessKey,
            $secret
        ));

        $steps['deleteByNames'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/variables/delete',
            ['names' => [$target['plainName'], $target['privateName']]],
            $accessKey,
            $secret
        ));
        $steps['rawAfterDelete'] = $this->selectedVariableFacts($target);
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
        $body = $this->json($payload === [] ? new stdClass() : $payload);
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

    private function normalizeSaved(array $data): array
    {
        return [
            'saved' => (bool)($data['saved'] ?? false),
            'variable_id_state' => (int)($data['variable_id'] ?? 0) > 0 ? 'present' : 'missing',
            'created' => (bool)($data['created'] ?? false),
        ];
    }

    private function normalizeVariableList(array $data, array $target): array
    {
        $variables = is_array($data['variables'] ?? null) ? $data['variables'] : [];
        $facts = [];
        foreach ($variables as $row) {
            if (!is_array($row)) {
                continue;
            }
            $name = (string)($row['name'] ?? '');
            if (!$this->targetVariableName($name, $target)) {
                continue;
            }
            $facts[] = [
                'name' => $this->variableNameFact($name, $target),
                'value' => $this->variableValueFact($name, (string)($row['value'] ?? '')),
                'scope' => (string)($row['scope'] ?? ''),
                'status' => (int)($row['status'] ?? -1),
                'app_ids' => $this->appIdsFact(is_array($row['app_ids'] ?? null) ? $row['app_ids'] : [], $target),
                'app_names_state' => empty($row['app_names']) ? 'empty' : 'present',
                'app_count' => (int)($row['app_count'] ?? -1),
                'created_at_state' => trim((string)($row['created_at'] ?? '')) === '' ? 'empty' : 'present',
                'updated_at_state' => trim((string)($row['updated_at'] ?? '')) === '' ? 'empty' : 'present',
            ];
        }
        usort($facts, static fn(array $left, array $right): int => $left['name'] <=> $right['name']);
        return $facts;
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

    private function selectedVariableFacts(array $target): array
    {
        return [
            'plain' => $this->variableRawFact($target['plainName'], $target),
            'private' => $this->variableRawFact($target['privateName'], $target),
            'lua' => $this->variableRawFact($target['luaName'], $target),
        ];
    }

    private function variableRawFact(string $name, array $target): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `id`, `name`, `value`, `scope`, `status` FROM `auth_remote_variables` WHERE `name` = ?',
            [$name]
        );
        if (!is_array($row)) {
            return ['exists' => false];
        }
        $variableId = (int)($row['id'] ?? 0);
        return [
            'exists' => true,
            'name' => $this->variableNameFact((string)$row['name'], $target),
            'value' => $this->variableValueFact((string)$row['name'], (string)($row['value'] ?? '')),
            'scope' => (string)($row['scope'] ?? ''),
            'status' => (int)($row['status'] ?? -1),
            'app_ids' => $this->variableAppIdsFact($variableId, $target),
        ];
    }

    private function variableValueFact(string $name, string $value): array|string
    {
        if (!str_starts_with($name, 'ace.lua.')) {
            return $value;
        }
        $decoded = json_decode($value, true);
        return [
            'format' => is_array($decoded) ? (string)($decoded['format'] ?? '') : 'invalid',
            'ciphertext_state' => is_array($decoded) && trim((string)($decoded['ciphertext'] ?? '')) !== '' ? 'present' : 'missing',
            'sourceSha256' => is_array($decoded) ? (string)($decoded['sourceSha256'] ?? '') : '',
        ];
    }

    private function variableAppIdsFact(int $variableId, array $target): array
    {
        if ($variableId <= 0) {
            return [];
        }
        $rows = $this->database->selectV2(
            'SELECT `app_id` FROM `auth_remote_variable_apps` WHERE `variable_id` = ? ORDER BY `app_id` ASC',
            [$variableId]
        );
        return $this->appIdsFact($this->columnInts($rows, 'app_id'), $target);
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
            'SELECT `app_id`, `action`, `message`, `ip` FROM `auth_audit_logs` WHERE `action` IN (?, ?) AND `message` LIKE ? ORDER BY `id` ASC',
            [
                'remote_vars_status',
                'remote_vars_delete',
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
                '[]',
                '1.0.0',
                'local_key_v1',
                'rsa_oaep_aes_256_gcm',
                '',
                '',
                'remote api variables parity',
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
        $this->deleteRemoteVariables();
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ? OR `app_code` LIKE ?', [self::PREFIX . 'APP_%', self::PREFIX . 'APP2_%']);
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

    private function deleteRemoteVariables(): void
    {
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_remote_variables` WHERE `name` LIKE ? OR `name` LIKE ?', [self::PREFIX . '%', 'ace.lua.' . self::PREFIX . '%']);
        $variableIds = $this->columnInts($rows, 'id');
        if ($variableIds !== []) {
            $this->execIn('DELETE FROM `auth_remote_variable_apps` WHERE `variable_id` IN (%s)', $variableIds);
            $this->execIn('DELETE FROM `auth_remote_variables` WHERE `id` IN (%s)', $variableIds);
        }
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

    private function targetVariableName(string $name, array $target): bool
    {
        return in_array($name, [$target['plainName'], $target['privateName'], $target['luaName']], true);
    }

    private function variableNameFact(string $name, array $target): string
    {
        return match ($name) {
            $target['plainName'] => '<plain>',
            $target['privateName'] => '<private>',
            $target['luaName'] => '<lua>',
            default => '<other>',
        };
    }

    private function appIdsFact(array $values, array $target): array
    {
        $facts = [];
        foreach ($values as $value) {
            $id = (int)$value;
            if ($id === (int)$target['appId']) {
                $facts[] = '<app>';
            } elseif ($id === (int)$target['secondAppId']) {
                $facts[] = '<second-app>';
            } elseif ($id > 0) {
                $facts[] = '<other>';
            }
        }
        $facts = array_values(array_unique($facts));
        sort($facts);
        return $facts;
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
        if ($target !== null && $id === (int)$target['secondAppId']) {
            return '<second-app>';
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

$check = new RemoteApiVariablesParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
