<?php
declare(strict_types=1);

final class InstallLiveDatabaseSmoke
{
    private const PREFIX = 'ace_live_';

    /** @var string[] */
    private array $databaseNames = [];

    /** @var string[] */
    private array $temporaryPaths = [];

    /** @var resource|null */
    private mixed $rustProcess = null;

    public function __construct(
        private readonly array $databaseConfig,
        private readonly string $projectRoot,
        private readonly string $rustBinary
    ) {
    }

    public function run(): int
    {
        if (!is_file($this->rustBinary)) {
            fwrite(STDERR, "RUST_BINARY_NOT_FOUND {$this->rustBinary}\n");
            return 1;
        }

        try {
            $emptyInstall = $this->runEmptyInstallSmoke();
            $legacyMigration = $this->runLegacyMigrationSmoke();
            echo 'INSTALL_LIVE_SMOKE ' . $this->json([
                'empty_install' => $emptyInstall,
                'legacy_migration' => $legacyMigration,
            ]) . "\n";
            echo "INSTALL_LIVE_SMOKE_OK empty install and legacy migration\n";
            return 0;
        } finally {
            $this->stopRustServer();
            $this->cleanupDatabases();
            $this->cleanupTemporaryPaths();
        }
    }

    private function runEmptyInstallSmoke(): array
    {
        $databaseName = $this->createTemporaryDatabase('empty');
        $paths = $this->createInstallPaths('empty', $databaseName);
        $port = $this->freePort();
        $this->startRustServer($port, $paths['config'], $paths['lock']);
        $baseUrl = "http://127.0.0.1:{$port}";
        $this->waitForHealth($baseUrl);

        $jar = [];
        $databasePage = $this->httpRaw($jar, 'GET', $baseUrl . '/install/?step=database');
        $databaseCsrf = $this->csrfToken((string)$databasePage['body']);
        $saveResponse = $this->httpRaw(
            $jar,
            'POST',
            $baseUrl . '/install/?step=database',
            http_build_query([
                'action' => 'save_database',
                'csrf_token' => $databaseCsrf,
                'host' => $this->databaseConfig['host'],
                'port' => (string)$this->databaseConfig['port'],
                'dbname' => $databaseName,
                'user' => $this->databaseConfig['user'],
                'pwd' => $this->databaseConfig['password'],
                'create_database' => '1',
            ], '', '&', PHP_QUERY_RFC3986)
        );
        $adminPage = $this->httpRaw($jar, 'GET', $baseUrl . '/install/?step=admin');
        $adminCsrf = $this->csrfToken((string)$adminPage['body']);
        $installResponse = $this->httpRaw(
            $jar,
            'POST',
            $baseUrl . '/install/?step=admin',
            http_build_query([
                'action' => 'install_system',
                'csrf_token' => $adminCsrf,
                'username' => 'admin',
                'password' => 'install-password-ok',
                'confirm_password' => 'install-password-ok',
            ], '', '&', PHP_QUERY_RFC3986)
        );
        $donePage = $this->httpRaw($jar, 'GET', $baseUrl . '/install/?step=done');
        $this->assertSame(200, (int)$databasePage['httpStatus'], 'empty install database page');
        $this->assertSame(
            303,
            (int)$saveResponse['httpStatus'],
            'empty install database submit ' . $this->safeErrorText((string)$saveResponse['body'], $databaseName)
        );
        $this->assertSame('/install/?step=admin', $this->headerValue($saveResponse['headers'], 'Location'), 'empty install database redirect');
        $this->assertSame(200, (int)$adminPage['httpStatus'], 'empty install admin page');
        $this->assertSame(
            303,
            (int)$installResponse['httpStatus'],
            'empty install admin submit ' . $this->safeErrorText((string)$installResponse['body'], $databaseName)
        );
        $this->assertSame('/install/?step=done', $this->headerValue($installResponse['headers'], 'Location'), 'empty install done redirect');
        $this->assertSame(200, (int)$donePage['httpStatus'], 'empty install done page');
        if (!is_file($paths['lock'])) {
            throw new RuntimeException('empty install lock file missing');
        }
        $this->assertInstalledDatabase($databaseName);
        $this->runRustCommand([
            'preflight',
            '--config',
            $paths['config'],
            '--database',
            '--public-root',
            $this->projectRoot . DIRECTORY_SEPARATOR . 'public',
            '--schema',
            $this->schemaPath(),
            '--storage-root',
            $this->projectRoot . DIRECTORY_SEPARATOR . 'storage',
        ], 'Database preflight passed.');
        $this->stopRustServer();

        return [
            'database' => $databaseName,
            'tables' => $this->tableCount($databaseName),
            'admin_count' => $this->tableCountWhere($databaseName, 'sub_admin', '1=1'),
            'lock' => 'present',
        ];
    }

    private function runLegacyMigrationSmoke(): array
    {
        $databaseName = $this->createTemporaryDatabase('legacy');
        $paths = $this->createInstallPaths('legacy', $databaseName);
        $this->runRustCommand([
            'migrate',
            '--config',
            $paths['config'],
            '--schema',
            $this->schemaPath(),
            '--id-strategy',
            'uuid_short_default',
        ], 'Schema migration applied:');
        $this->createLegacyDrift($databaseName);
        $this->runRustCommand([
            'migrate',
            '--config',
            $paths['config'],
            '--schema',
            $this->schemaPath(),
            '--id-strategy',
            'uuid_short_default',
        ], 'Schema migration applied:');
        $this->assertColumnExists($databaseName, 'auth_apps', 'api_token');
        $this->assertColumnExists($databaseName, 'auth_cards', 'card_type');
        $this->assertIndexExists($databaseName, 'auth_sessions', 'idx_auth_sessions_app_ip');
        $this->assertSame(1, $this->tableCountWhere($databaseName, 'site_settings', '`id` = 1'), 'legacy site settings seed');
        $this->runRustCommand([
            'preflight',
            '--config',
            $paths['config'],
            '--database',
            '--public-root',
            $this->projectRoot . DIRECTORY_SEPARATOR . 'public',
            '--schema',
            $this->schemaPath(),
            '--storage-root',
            $this->projectRoot . DIRECTORY_SEPARATOR . 'storage',
        ], 'Database preflight passed.');

        return [
            'database' => $databaseName,
            'restored_columns' => ['auth_apps.api_token', 'auth_cards.card_type'],
            'restored_indexes' => ['auth_sessions.idx_auth_sessions_app_ip'],
            'site_settings_seed' => 'present',
        ];
    }

    private function createTemporaryDatabase(string $suffix): string
    {
        $databaseName = self::PREFIX . $suffix . '_' . date('YmdHis') . '_' . bin2hex(random_bytes(3));
        $pdo = $this->serverPdo();
        $pdo->exec($this->dropDatabaseSql($databaseName));
        $pdo->exec($this->createDatabaseSql($databaseName));
        $this->databaseNames[] = $databaseName;
        return $databaseName;
    }

    private function createInstallPaths(string $suffix, string $databaseName): array
    {
        $base = $this->projectRoot
            . DIRECTORY_SEPARATOR . 'storage'
            . DIRECTORY_SEPARATOR . 'runtime-cache'
            . DIRECTORY_SEPARATOR . 'live-install-' . $suffix . '-' . bin2hex(random_bytes(4));
        if (!is_dir($base) && !mkdir($base, 0777, true)) {
            throw new RuntimeException("cannot create temporary directory: {$base}");
        }
        $this->temporaryPaths[] = $base;
        $config = $base . DIRECTORY_SEPARATOR . 'local.php';
        $lock = $base . DIRECTORY_SEPARATOR . 'install.lock';
        file_put_contents($config, $this->configText($databaseName));
        return ['base' => $base, 'config' => $config, 'lock' => $lock];
    }

    private function configText(string $databaseName): string
    {
        return "<?php\n"
            . "defined('IN_CRONLITE') or die('Access Denied');\n\n"
            . "\$dbconfig = [\n"
            . "    'host' => " . var_export($this->databaseConfig['host'], true) . ",\n"
            . "    'port' => " . (int)$this->databaseConfig['port'] . ",\n"
            . "    'user' => " . var_export($this->databaseConfig['user'], true) . ",\n"
            . "    'pwd' => " . var_export($this->databaseConfig['password'], true) . ",\n"
            . "    'dbname' => " . var_export($databaseName, true) . ",\n"
            . "];\n"
            . "define('SYS_KEY', '" . bin2hex(random_bytes(32)) . "');\n"
            . "define('AUTH_ADMIN_TOKEN_HASH', '" . hash('sha256', bin2hex(random_bytes(24))) . "');\n"
            . "define('AUTH_CORS_ORIGINS', '');\n"
            . "define('NETWORK_AUTH_ID_STRATEGY', 'uuid_short_default');\n";
    }

    private function startRustServer(int $port, string $configPath, string $lockPath): void
    {
        $this->stopRustServer();
        $logPrefix = $this->projectRoot . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'install-live-' . $port;
        $command = [
            $this->rustBinary,
            'serve',
            '--listen',
            "127.0.0.1:{$port}",
            '--config',
            $configPath,
            '--public-root',
            $this->projectRoot . DIRECTORY_SEPARATOR . 'public',
            '--schema',
            $this->schemaPath(),
            '--install-lock',
            $lockPath,
        ];
        $this->rustProcess = proc_open(
            $command,
            [
                0 => ['pipe', 'r'],
                1 => ['file', $logPrefix . '.out.log', 'a'],
                2 => ['file', $logPrefix . '.err.log', 'a'],
            ],
            $pipes,
            $this->projectRoot
        );
        if (!is_resource($this->rustProcess)) {
            throw new RuntimeException('cannot start Rust install smoke server');
        }
        if (isset($pipes[0]) && is_resource($pipes[0])) {
            fclose($pipes[0]);
        }
    }

    private function stopRustServer(): void
    {
        if (!is_resource($this->rustProcess)) {
            $this->rustProcess = null;
            return;
        }
        $status = proc_get_status($this->rustProcess);
        if (($status['running'] ?? false) === true) {
            proc_terminate($this->rustProcess);
            usleep(300000);
        }
        proc_close($this->rustProcess);
        $this->rustProcess = null;
    }

    private function waitForHealth(string $baseUrl): void
    {
        $deadline = microtime(true) + 15;
        do {
            $jar = [];
            $response = $this->httpRaw($jar, 'GET', $baseUrl . '/health');
            if ((int)$response['httpStatus'] === 200 && str_contains((string)$response['body'], '"runtime":"rust"')) {
                return;
            }
            usleep(250000);
        } while (microtime(true) < $deadline);
        throw new RuntimeException('Rust install smoke server health check failed');
    }

    private function runRustCommand(array $arguments, string $successMarker): string
    {
        $command = array_merge([$this->rustBinary], $arguments);
        $process = proc_open(
            $command,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->projectRoot
        );
        if (!is_resource($process)) {
            throw new RuntimeException('cannot start Rust command');
        }
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]) ?: '';
        $stderr = stream_get_contents($pipes[2]) ?: '';
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        if ($exitCode !== 0 || !str_contains($stdout, $successMarker)) {
            throw new RuntimeException("Rust command failed: exit={$exitCode} output={$stdout}{$stderr}");
        }
        return $stdout;
    }

    private function createLegacyDrift(string $databaseName): void
    {
        $pdo = $this->databasePdo($databaseName);
        $pdo->exec('ALTER TABLE `auth_apps` DROP COLUMN `api_token`');
        $pdo->exec('ALTER TABLE `auth_cards` DROP COLUMN `card_type`');
        $pdo->exec('DROP INDEX `idx_auth_sessions_app_ip` ON `auth_sessions`');
        $pdo->exec('DELETE FROM `site_settings` WHERE `id` = 1');
    }

    private function assertInstalledDatabase(string $databaseName): void
    {
        if ($this->tableCount($databaseName) < 20) {
            throw new RuntimeException('empty install created too few tables');
        }
        $this->assertSame(1, $this->tableCountWhere($databaseName, 'sub_admin', "`username` = 'admin'"), 'empty install admin account');
        $this->assertSame(1, $this->tableCountWhere($databaseName, 'site_settings', '`id` = 1'), 'empty install site settings');
        $this->assertColumnExists($databaseName, 'auth_apps', 'api_token');
        $this->assertColumnExists($databaseName, 'auth_cards', 'card_type');
        $this->assertIndexExists($databaseName, 'auth_sessions', 'idx_auth_sessions_app_ip');
    }

    private function tableCount(string $databaseName): int
    {
        $row = $this->serverPdo()->prepare('SELECT COUNT(*) AS count FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?');
        $row->execute([$databaseName]);
        return (int)$row->fetchColumn();
    }

    private function tableCountWhere(string $databaseName, string $table, string $where): int
    {
        $sql = 'SELECT COUNT(*) FROM ' . $this->quoteIdentifier($databaseName) . '.' . $this->quoteIdentifier($table) . ' WHERE ' . $where;
        return (int)$this->serverPdo()->query($sql)->fetchColumn();
    }

    private function assertColumnExists(string $databaseName, string $table, string $column): void
    {
        $statement = $this->serverPdo()->prepare(
            'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?'
        );
        $statement->execute([$databaseName, $table, $column]);
        $this->assertSame(1, (int)$statement->fetchColumn(), "column {$table}.{$column}");
    }

    private function assertIndexExists(string $databaseName, string $table, string $index): void
    {
        $statement = $this->serverPdo()->prepare(
            'SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND INDEX_NAME = ?'
        );
        $statement->execute([$databaseName, $table, $index]);
        if ((int)$statement->fetchColumn() < 1) {
            throw new RuntimeException("index {$table}.{$index} missing");
        }
    }

    private function httpRaw(array &$jar, string $method, string $url, string $body = ''): array
    {
        $headers = ['Accept: text/html,application/xhtml+xml,application/json'];
        if ($method === 'POST') {
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        }
        if ($jar !== []) {
            $cookiePairs = [];
            foreach ($jar as $name => $value) {
                $cookiePairs[] = $name . '=' . $value;
            }
            $headers[] = 'Cookie: ' . implode('; ', $cookiePairs);
        }
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'content' => $body,
                'ignore_errors' => true,
                'timeout' => 30,
                'follow_location' => 0,
            ],
        ]);
        $raw = @file_get_contents($url, false, $context);
        $responseHeaders = $http_response_header ?? [];
        $this->storeCookies($jar, $responseHeaders);
        return [
            'httpStatus' => $this->httpStatus($responseHeaders),
            'headers' => $responseHeaders,
            'body' => is_string($raw) ? $raw : '',
        ];
    }

    private function storeCookies(array &$jar, array $headers): void
    {
        foreach ($headers as $header) {
            if (stripos((string)$header, 'Set-Cookie:') !== 0) {
                continue;
            }
            $cookie = trim(substr((string)$header, strlen('Set-Cookie:')));
            $pair = strtok($cookie, ';') ?: '';
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            if ($name === '') {
                continue;
            }
            if ($value === '' || $value === 'deleted' || stripos($cookie, 'Max-Age=0') !== false) {
                unset($jar[$name]);
                continue;
            }
            $jar[$name] = $value;
        }
    }

    private function csrfToken(string $body): string
    {
        if (preg_match('/name="csrf_token" value="([a-f0-9]{64})"/su', $body, $matches) !== 1) {
            throw new RuntimeException('csrf token missing');
        }
        return (string)$matches[1];
    }

    private function headerValue(array $headers, string $name): string
    {
        foreach ($headers as $header) {
            $parts = explode(':', (string)$header, 2);
            if (count($parts) === 2 && strcasecmp(trim($parts[0]), $name) === 0) {
                return trim($parts[1]);
            }
        }
        return '';
    }

    private function safeErrorText(string $body, string $databaseName): string
    {
        if (preg_match('/<div class="error-box">(.*?)<\/div>/su', $body, $matches) !== 1) {
            return 'error=none';
        }
        $text = trim(html_entity_decode(strip_tags((string)$matches[1]), ENT_QUOTES, 'UTF-8'));
        $sensitiveValues = [
            $this->databaseConfig['host'],
            $this->databaseConfig['user'],
            $this->databaseConfig['password'],
            $databaseName,
        ];
        foreach ($sensitiveValues as $value) {
            if ($value !== '') {
                $text = str_replace((string)$value, '[redacted]', $text);
            }
        }
        return 'error=' . $text;
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

    private function freePort(): int
    {
        for ($port = 18150; $port <= 18250; $port++) {
            $socket = @stream_socket_server("tcp://127.0.0.1:{$port}", $errorCode, $errorMessage);
            if (is_resource($socket)) {
                fclose($socket);
                return $port;
            }
        }
        throw new RuntimeException('no free local port for install live smoke');
    }

    private function serverPdo(): PDO
    {
        return new PDO(
            'mysql:host=' . $this->databaseConfig['host'] . ';port=' . $this->databaseConfig['port'] . ';charset=utf8mb4',
            $this->databaseConfig['user'],
            $this->databaseConfig['password'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    }

    private function databasePdo(string $databaseName): PDO
    {
        return new PDO(
            'mysql:host=' . $this->databaseConfig['host'] . ';port=' . $this->databaseConfig['port'] . ';dbname=' . $databaseName . ';charset=utf8mb4',
            $this->databaseConfig['user'],
            $this->databaseConfig['password'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
    }

    private function cleanupDatabases(): void
    {
        if ($this->databaseNames === []) {
            return;
        }
        $pdo = $this->serverPdo();
        foreach (array_reverse($this->databaseNames) as $databaseName) {
            try {
                $pdo->exec($this->dropDatabaseSql($databaseName));
            } catch (Throwable $exception) {
                fwrite(STDERR, "INSTALL_LIVE_SMOKE_DB_CLEANUP_FAILED database={$databaseName}\n");
            }
        }
        $this->databaseNames = [];
    }

    private function cleanupTemporaryPaths(): void
    {
        foreach (array_reverse($this->temporaryPaths) as $path) {
            $this->removeTree($path);
        }
        $this->temporaryPaths = [];
    }

    private function removeTree(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        $items = scandir($path);
        foreach (is_array($items) ? $items : [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $child = $path . DIRECTORY_SEPARATOR . $item;
            if (is_dir($child)) {
                $this->removeTree($child);
                continue;
            }
            @unlink($child);
        }
        @rmdir($path);
    }

    private function createDatabaseSql(string $databaseName): string
    {
        return 'CREATE DATABASE ' . $this->quoteIdentifier($databaseName) . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
    }

    private function dropDatabaseSql(string $databaseName): string
    {
        return 'DROP DATABASE IF EXISTS ' . $this->quoteIdentifier($databaseName);
    }

    private function quoteIdentifier(string $identifier): string
    {
        return '`' . str_replace('`', '``', $identifier) . '`';
    }

    private function schemaPath(): string
    {
        return $this->projectRoot . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'install' . DIRECTORY_SEPARATOR . 'schema.sql';
    }

    private function assertSame(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected !== $actual) {
            throw new RuntimeException("{$label} expected=" . $this->json($expected) . ' actual=' . $this->json($actual));
        }
    }

    private function json(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}

function installLiveEnv(string $name): string
{
    $value = getenv($name);
    return is_string($value) ? trim($value) : '';
}

function installLiveDatabaseConfigFromEnvironment(): ?array
{
    $host = installLiveEnv('ACE_DB_LIVE_HOST');
    $user = installLiveEnv('ACE_DB_LIVE_USER');
    $password = installLiveEnv('ACE_DB_LIVE_PASSWORD');
    if ($host === '' && $user === '' && $password === '') {
        return null;
    }
    if ($host === '' || $user === '' || $password === '') {
        fwrite(STDERR, "DB_LIVE_CONFIG_INCOMPLETE\n");
        exit(1);
    }
    return [
        'host' => $host,
        'port' => installLiveEnv('ACE_DB_LIVE_PORT') !== '' ? installLiveEnv('ACE_DB_LIVE_PORT') : '3306',
        'user' => $user,
        'password' => $password,
    ];
}

$databaseConfig = installLiveDatabaseConfigFromEnvironment();
if ($databaseConfig === null) {
    echo "INSTALL_LIVE_SMOKE_BLOCKED missing=ACE_DB_LIVE_HOST|ACE_DB_LIVE_USER|ACE_DB_LIVE_PASSWORD\n";
    echo "LIVE_SMOKE_BLOCKED install empty database and legacy migration smoke requires live database credentials\n";
    exit(0);
}

$projectRoot = dirname(__DIR__);
$rustBinary = getenv('ACE_RUST_BIN') ?: $projectRoot . DIRECTORY_SEPARATOR . 'target' . DIRECTORY_SEPARATOR . 'debug' . DIRECTORY_SEPARATOR . (DIRECTORY_SEPARATOR === '\\' ? 'network-auth-rust.exe' : 'network-auth-rust');
$smoke = new InstallLiveDatabaseSmoke($databaseConfig, $projectRoot, $rustBinary);
exit($smoke->run());
