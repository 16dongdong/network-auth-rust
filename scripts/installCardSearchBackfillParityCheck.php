<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$rustProjectRoot = dirname(__DIR__);
$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Support\CardKeyFactory;
use NetworkAuth\Support\CardSearchIndex;
use NetworkAuth\Support\ClientApiConfig;

final class InstallCardSearchBackfillParityCheck
{
    private const PREFIX = 'E2E_CSB_';

    private string $appCode = '';
    private int $appId = 0;
    private int $cardId = 0;

    public function __construct(
        private readonly SpringMySQLi $database,
        private readonly string $systemKey,
        private readonly string $rustProjectRoot,
        private readonly string $rustBinary,
        private readonly string $configPath
    ) {
    }

    public function run(): int
    {
        $this->cleanup();
        try {
            $cardKey = self::PREFIX . $this->randomAlpha(10);
            $this->appCode = self::PREFIX . $this->randomAlpha(10);
            $this->appId = $this->insertApp($this->appCode);
            $this->cardId = $this->insertLegacyCardWithoutSearchTokens($this->appId, $this->appCode, $cardKey);

            $expectedHashes = CardSearchIndex::cardTokenHashes($cardKey, $this->systemKey);
            if ($expectedHashes === []) {
                throw new RuntimeException('expected card search token hashes are empty');
            }
            $this->assertTokenCount(0, 'before migrate');
            $this->runRustMigrate();
            $this->assertBackfilledHashes($expectedHashes);
            echo "PARITY_OK install card search token backfill\n";
            return 0;
        } finally {
            $this->cleanup();
        }
    }

    private function insertApp(string $appCode): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appCode, 'token_' . $this->randomAlpha(12), 'Backfill parity app', 1, 10, 300, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, $this->json(ClientApiConfig::defaults()), '1.0.0', 'local_key_v1', 'rsa_oaep_aes_256_gcm', '', '', 'card search backfill parity']
        );
    }

    private function insertLegacyCardWithoutSearchTokens(int $appId, string $appCode, string $cardKey): int
    {
        $cardId = (int)$this->exec(
            'INSERT INTO `auth_cards` (`app_id`, `card_hash`, `card_cipher`, `card_fingerprint`, `card_type`, `duration_seconds`, `total_uses`, `remaining_uses`, `max_devices`, `card_structure`, `prefix`, `unbind_limit`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, hash('sha256', $appCode . ':' . $cardKey), Crypto::encryptProtectedText($cardKey, $this->systemKey), CardKeyFactory::fingerprint($cardKey), 'time', 86400, 0, 0, 10, 'custom', 'E2E', 0, 1]
        );
        $this->exec('DELETE FROM `auth_card_search_tokens` WHERE `app_id` = ? AND `card_id` = ?', [$appId, $cardId]);
        return $cardId;
    }

    private function runRustMigrate(): void
    {
        if (!is_file($this->rustBinary)) {
            throw new RuntimeException("Rust binary not found: {$this->rustBinary}");
        }
        if (!is_file($this->configPath)) {
            throw new RuntimeException("Config file not found: {$this->configPath}");
        }
        $command = [
            $this->rustBinary,
            'migrate',
            '--config',
            $this->configPath,
            '--schema',
            $this->rustProjectRoot . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'schema.sql',
        ];
        $process = proc_open(
            $command,
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->rustProjectRoot
        );
        if (!is_resource($process)) {
            throw new RuntimeException('cannot start Rust migrate');
        }
        $stdout = stream_get_contents($pipes[1]) ?: '';
        $stderr = stream_get_contents($pipes[2]) ?: '';
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        if ($exitCode !== 0) {
            throw new RuntimeException("Rust migrate failed ({$exitCode}): {$stdout}{$stderr}");
        }
        if (!str_contains($stdout, 'Schema migration applied:')) {
            throw new RuntimeException("Rust migrate output missing success marker: {$stdout}");
        }
    }

    private function assertBackfilledHashes(array $expectedHashes): void
    {
        $rows = $this->database->selectV2(
            'SELECT `token_hash` FROM `auth_card_search_tokens` WHERE `app_id` = ? AND `card_id` = ? ORDER BY `token_hash` ASC',
            [$this->appId, $this->cardId]
        );
        $actualHashes = array_map(static fn(array $row): string => (string)($row['token_hash'] ?? ''), is_array($rows) ? $rows : []);
        sort($expectedHashes);
        if ($actualHashes !== $expectedHashes) {
            throw new RuntimeException('backfilled card search token hashes do not match PHP CardSearchIndex');
        }
    }

    private function assertTokenCount(int $expectedCount, string $stage): void
    {
        $row = $this->database->selectRowV2(
            'SELECT COUNT(*) AS `count` FROM `auth_card_search_tokens` WHERE `app_id` = ? AND `card_id` = ?',
            [$this->appId, $this->cardId]
        );
        $actualCount = (int)($row['count'] ?? -1);
        if ($actualCount !== $expectedCount) {
            throw new RuntimeException("unexpected token count {$stage}: {$actualCount}");
        }
    }

    private function cleanup(): void
    {
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . '%']);
        foreach (is_array($rows) ? $rows : [] as $row) {
            $appId = (int)($row['id'] ?? 0);
            if ($appId <= 0) {
                continue;
            }
            $this->exec('DELETE FROM `auth_card_search_tokens` WHERE `app_id` = ?', [$appId]);
            $this->exec('DELETE FROM `auth_cards` WHERE `app_id` = ?', [$appId]);
            $this->exec('DELETE FROM `auth_apps` WHERE `id` = ?', [$appId]);
        }
    }

    private function exec(string $sql, array $params): int|string
    {
        $result = $this->database->exec($sql, $params);
        if ($result === false) {
            throw new RuntimeException($this->database->getError() ?: 'database statement failed');
        }
        return $result;
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

$rustBinary = getenv('ACE_RUST_BIN') ?: $rustProjectRoot . DIRECTORY_SEPARATOR . 'target' . DIRECTORY_SEPARATOR . 'debug' . DIRECTORY_SEPARATOR . (DIRECTORY_SEPARATOR === '\\' ? 'network-auth-rust.exe' : 'network-auth-rust');
$configPath = getenv('ACE_CONFIG_PATH') ?: $phpProjectRoot . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'local.php';

$check = new InstallCardSearchBackfillParityCheck(
    $DB,
    (string)SYS_KEY,
    $rustProjectRoot,
    $rustBinary,
    $configPath
);
exit($check->run());
