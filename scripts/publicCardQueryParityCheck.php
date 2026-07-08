<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Support\CardKeyFactory;
use NetworkAuth\Support\ClientApiConfig;

final class PublicCardQueryParityCheck
{
    private const PREFIX = 'E2E_PCQ_';

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
            $diffs = $this->diff($phpResult, $rustResult, 'publicCardQuery');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK public card query\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $suffix = strtoupper($name) . '_' . strtoupper($this->randomAlpha(8));
        $enabledAppCode = self::PREFIX . 'EN_' . $suffix;
        $disabledAppCode = self::PREFIX . 'DIS_' . $suffix;
        $virtualAppCode = self::PREFIX . 'VIR_' . $suffix;
        $enabledAppId = $this->insertApp($enabledAppCode, true, true);
        $disabledAppId = $this->insertApp($disabledAppCode, false, true);
        $virtualAppId = $this->insertApp($virtualAppCode, true, false);

        $cards = [
            'time' => $this->insertCard($enabledAppId, $enabledAppCode, 'CARDTIME' . $this->randomAlpha(24), 'time', 1, '2099-01-02 03:04:05', 7200, 0, 0, 5, 3, 1),
            'count' => $this->insertCard($enabledAppId, $enabledAppCode, 'CARDCOUNT' . $this->randomAlpha(23), 'count', 1, '2026-02-03 04:05:06', 0, 10, 7, 2, 0, 0),
            'permanent' => $this->insertCard($enabledAppId, $enabledAppCode, 'CARDPERM' . $this->randomAlpha(24), 'permanent', 1, '2026-03-04 05:06:07', 0, 0, 0, 9, 1, 1),
            'disabled' => $this->insertCard($enabledAppId, $enabledAppCode, 'CARDDISABLED' . $this->randomAlpha(20), 'time', 2, '2026-04-05 06:07:08', 7200, 0, 0, 1, 0, 0),
            'expired' => $this->insertCard($enabledAppId, $enabledAppCode, 'CARDEXPIRED' . $this->randomAlpha(21), 'time', 1, '2020-01-01 00:00:00', 60, 0, 0, 1, 0, 0),
        ];

        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'enabledAppCode' => $enabledAppCode,
            'disabledAppCode' => $disabledAppCode,
            'virtualAppCode' => $virtualAppCode,
            'appIds' => [$enabledAppId, $disabledAppId, $virtualAppId],
            'cards' => $cards,
            'virtualCardKey' => 'virtual card ' . strtolower($this->randomAlpha(18)),
        ];
    }

    private function runTarget(array $target): array
    {
        $steps = [];
        $steps['methodGet'] = $this->normalizeError($this->httpGet($this->url($target, '/card/query')));
        $steps['wrongContentType'] = $this->normalizeError($this->httpPostRaw($this->url($target, '/card/query'), ['Content-Type' => 'text/plain'], 'card_key=abc'));
        $steps['missingApp'] = $this->normalizeError($this->cardQuery($target, '', ['card_key' => $target['cards']['time']]));
        $steps['disabled'] = $this->normalizeError($this->cardQuery($target, $target['disabledAppCode'], ['card_key' => $target['cards']['time']]));
        $steps['missingCardKey'] = $this->normalizeError($this->cardQuery($target, $target['enabledAppCode'], []));
        $steps['badCardKey'] = $this->normalizeError($this->cardQuery($target, $target['enabledAppCode'], ['card_key' => "bad\nkey"]));
        $steps['notFound'] = $this->normalizeError($this->cardQuery($target, $target['enabledAppCode'], ['card_key' => 'NO_SUCH_CARD_123456']));
        $steps['disabledCard'] = $this->normalizeError($this->cardQuery($target, $target['enabledAppCode'], ['card_key' => $target['cards']['disabled']]));
        $steps['expiredCard'] = $this->normalizeError($this->cardQuery($target, $target['enabledAppCode'], ['card_key' => $target['cards']['expired']]));
        $steps['timeCard'] = $this->normalizeSuccess($this->cardQuery($target, $target['enabledAppCode'], ['card_key' => $target['cards']['time']]), false);
        $steps['countCard'] = $this->normalizeSuccess($this->cardQuery($target, $target['enabledAppCode'], ['card_key' => $target['cards']['count']]), false);
        $steps['permanentCard'] = $this->normalizeSuccess($this->cardQuery($target, $target['enabledAppCode'], ['card_key' => $target['cards']['permanent']]), false);
        $steps['virtualCard'] = $this->normalizeSuccess($this->cardQuery($target, $target['virtualAppCode'], ['card_key' => $target['virtualCardKey']]), true);
        $steps['virtualRejectControlChar'] = $this->normalizeError($this->cardQuery($target, $target['virtualAppCode'], ['card_key' => "virtual\nbad"]));
        return $steps;
    }

    private function cardQuery(array $target, string $appCode, array $payload): array
    {
        $headers = ['Content-Type' => 'application/json'];
        if ($appCode !== '') {
            $headers['X-App-Code'] = $appCode;
        }
        return $this->httpPostRaw($this->url($target, '/card/query'), $headers, $this->json($payload));
    }

    private function url(array $target, string $route): string
    {
        return $target['baseUrl'] . '/api/v1/index.php?route=' . rawurlencode($route);
    }

    private function normalizeSuccess(array $response, bool $dynamicExpiry): array
    {
        $body = $response['body'];
        $data = is_array($body) ? ($body['data'] ?? []) : [];
        if (!is_array($data)) {
            $data = [];
        }
        return [
            'httpStatus' => $response['httpStatus'],
            'code' => is_array($body) ? (int)($body['code'] ?? -1) : -1,
            'keys' => array_keys($data),
            'card_fingerprint_state' => trim((string)($data['card_fingerprint'] ?? '')) === '' ? 'empty' : 'present',
            'card_type' => (string)($data['card_type'] ?? ''),
            'status' => (int)($data['status'] ?? -1),
            'used_at_state' => trim((string)($data['used_at'] ?? '')) === '' ? 'empty' : 'present',
            'expires_at' => $dynamicExpiry ? '<dynamic>' : (int)($data['expires_at'] ?? -1),
            'remaining_uses' => (int)($data['remaining_uses'] ?? -1),
            'max_devices' => (int)($data['max_devices'] ?? -1),
            'unbind_limit' => (int)($data['unbind_limit'] ?? -1),
            'unbind_count' => (int)($data['unbind_count'] ?? -1),
        ];
    }

    private function normalizeError(array $response): array
    {
        $body = $response['body'];
        return [
            'httpStatus' => $response['httpStatus'],
            'code' => is_array($body) ? (int)($body['code'] ?? -1) : -1,
            'error' => is_array($body) ? (string)($body['error'] ?? '') : '<non-json>',
        ];
    }

    private function insertApp(string $appCode, bool $webCardQueryEnabled, bool $verificationEnabled): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appCode, ClientApiConfig::generateToken(), 'Public Card Query Parity', 1, 50, 300, 1, $verificationEnabled ? 1 : 0, 1, 0, 0, $webCardQueryEnabled ? 1 : 0, 0, 0, 0, 0, $this->json(ClientApiConfig::defaults()), '1.0.0', 'local_key_v1', 'rsa_oaep_aes_256_gcm', '', '', 'public card query parity']
        );
    }

    private function insertCard(
        int $appId,
        string $appCode,
        string $cardKey,
        string $cardType,
        int $status,
        string $usedAt,
        int $durationSeconds,
        int $totalUses,
        int $remainingUses,
        int $maxDevices,
        int $unbindLimit,
        int $unbindCount
    ): string {
        $this->exec(
            'INSERT INTO `auth_cards` (`app_id`, `card_hash`, `card_cipher`, `card_fingerprint`, `card_type`, `duration_seconds`, `total_uses`, `remaining_uses`, `max_devices`, `card_structure`, `prefix`, `unbind_limit`, `unbind_count`, `status`, `used_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, hash('sha256', $appCode . ':' . $cardKey), Crypto::encryptProtectedText($cardKey, $this->systemKey), CardKeyFactory::fingerprint($cardKey), $cardType, $durationSeconds, $totalUses, $remainingUses, $maxDevices, 'custom', 'E2E', $unbindLimit, $unbindCount, $status, $usedAt]
        );
        return $cardKey;
    }

    private function cleanup(): void
    {
        $apps = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . '%']);
        foreach ($apps as $app) {
            $this->deleteAppRows((int)$app['id']);
        }
    }

    private function deleteAppRows(int $appId): void
    {
        foreach ([
            'auth_message_actions',
            'auth_messages',
            'auth_security_reports',
            'auth_sessions',
            'auth_devices',
            'auth_login_challenges',
            'auth_card_search_tokens',
            'auth_cards',
            'auth_audit_logs',
            'auth_remote_configs',
        ] as $table) {
            if ($this->tableExists($table)) {
                $this->exec("DELETE FROM `{$table}` WHERE `app_id` = ?", [$appId]);
            }
        }
        $this->exec('DELETE FROM `auth_apps` WHERE `id` = ?', [$appId]);
    }

    private function httpGet(string $url): array
    {
        return $this->httpRequest($url, 'GET', [], '');
    }

    private function httpPostRaw(string $url, array $headers, string $body): array
    {
        return $this->httpRequest($url, 'POST', $headers, $body);
    }

    private function httpRequest(string $url, string $method, array $headers, string $body): array
    {
        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = "{$name}: {$value}";
        }
        $responseHeaders = [];
        $options = [
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headerLines),
                'content' => $body,
                'ignore_errors' => true,
                'timeout' => 20,
            ],
        ];
        $content = file_get_contents($url, false, stream_context_create($options));
        if (!isset($http_response_header) || !is_array($http_response_header)) {
            throw new RuntimeException("HTTP request failed: {$url}");
        }
        $responseHeaders = $http_response_header;
        return [
            'httpStatus' => $this->httpStatus($responseHeaders),
            'body' => $this->decodeJson(is_string($content) ? $content : ''),
        ];
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

    private function decodeJson(string $body): mixed
    {
        $decoded = json_decode($body, true);
        return json_last_error() === JSON_ERROR_NONE ? $decoded : $body;
    }

    private function exec(string $sql, array $params): int|string
    {
        $result = $this->database->exec($sql, $params);
        if ($result === false) {
            throw new RuntimeException($this->database->getError() ?: 'database statement failed');
        }
        return $result;
    }

    private function tableExists(string $tableName): bool
    {
        return is_array($this->database->selectRowV2('SHOW TABLES LIKE ?', [$tableName]));
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
        return $left === $right ? [] : [$path . ' php=' . $this->json($left) . ' rust=' . $this->json($right)];
    }

    private function printResult(string $label, array $result): void
    {
        echo strtoupper($label) . ' ' . $this->json($result) . "\n";
    }

    private function json(mixed $value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
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

$database = $DB ?? null;
if (!$database instanceof SpringMySQLi) {
    fwrite(STDERR, "DB_NOT_CONFIGURED\n");
    exit(1);
}

$systemKey = defined('SYS_KEY') ? (string)SYS_KEY : '';
if ($systemKey === '') {
    fwrite(STDERR, "SYS_KEY_MISSING\n");
    exit(1);
}

$phpBaseUrl = getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081';
$rustBaseUrl = getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080';

exit((new PublicCardQueryParityCheck($database, $systemKey, $phpBaseUrl, $rustBaseUrl))->run());
