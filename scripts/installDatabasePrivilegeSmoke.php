<?php
declare(strict_types=1);

define('IN_CRONLITE', true);

final class InstallDatabasePrivilegeSmoke
{
    public function __construct(private readonly array $databaseConfig)
    {
    }

    public function run(): int
    {
        $pdo = $this->connect();
        $databaseName = $this->databaseName();
        $created = false;
        try {
            $pdo->exec($this->createDatabaseSql($databaseName));
            $created = true;
        } catch (PDOException $exception) {
            if ($this->isCreatePrivilegeMissing($exception)) {
                echo "CREATE_DATABASE_PRIVILEGE_MISSING sqlstate={$exception->getCode()}\n";
                echo "LIVE_SMOKE_BLOCKED install empty/legacy database smoke requires CREATE DATABASE privilege\n";
                return 0;
            }
            fwrite(STDERR, "CREATE_DATABASE_PRIVILEGE_CHECK_FAILED sqlstate={$exception->getCode()}\n");
            fwrite(STDERR, $this->safeMessage($exception) . "\n");
            return 1;
        }

        try {
            $pdo->exec($this->dropDatabaseSql($databaseName));
            $created = false;
            echo "CREATE_DATABASE_PRIVILEGE_OK database={$databaseName}\n";
            return 0;
        } catch (PDOException $exception) {
            fwrite(STDERR, "CREATE_DATABASE_PRIVILEGE_CLEANUP_FAILED sqlstate={$exception->getCode()}\n");
            fwrite(STDERR, $this->safeMessage($exception) . "\n");
            return 1;
        } finally {
            if ($created) {
                $this->dropIfExists($pdo, $databaseName);
            }
        }
    }

    private function connect(): PDO
    {
        $host = (string)($this->databaseConfig['host'] ?? '127.0.0.1');
        $port = (string)($this->databaseConfig['port'] ?? '3306');
        $user = (string)($this->databaseConfig['user'] ?? '');
        $password = (string)($this->databaseConfig['pwd'] ?? '');
        $dsn = "mysql:host={$host};port={$port};charset=utf8mb4";
        return new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    private function databaseName(): string
    {
        return 'aceRustPrivilege' . date('YmdHis') . bin2hex(random_bytes(4));
    }

    private function createDatabaseSql(string $databaseName): string
    {
        return 'CREATE DATABASE ' . $this->quoteIdentifier($databaseName)
            . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
    }

    private function dropDatabaseSql(string $databaseName): string
    {
        return 'DROP DATABASE ' . $this->quoteIdentifier($databaseName);
    }

    private function dropIfExists(PDO $pdo, string $databaseName): void
    {
        try {
            $pdo->exec('DROP DATABASE IF EXISTS ' . $this->quoteIdentifier($databaseName));
        } catch (PDOException $exception) {
            fwrite(STDERR, "CREATE_DATABASE_PRIVILEGE_CLEANUP_FAILED sqlstate={$exception->getCode()}\n");
        }
    }

    private function quoteIdentifier(string $identifier): string
    {
        return '`' . str_replace('`', '``', $identifier) . '`';
    }

    private function isCreatePrivilegeMissing(PDOException $exception): bool
    {
        $info = $exception->errorInfo;
        $mysqlCode = is_array($info) && isset($info[1]) ? (int)$info[1] : 0;
        return in_array($mysqlCode, [1044, 1045, 1142, 1227], true);
    }

    private function safeMessage(PDOException $exception): string
    {
        return preg_replace('/password\\s*=\\s*[^\\s;]+/i', 'password=[redacted]', $exception->getMessage()) ?? 'unknown error';
    }
}

function envValue(string $name): string
{
    $value = getenv($name);
    return is_string($value) ? trim($value) : '';
}

function databaseConfigFromEnvironment(): ?array
{
    $host = envValue('ACE_DB_LIVE_HOST');
    $user = envValue('ACE_DB_LIVE_USER');
    $password = envValue('ACE_DB_LIVE_PASSWORD');
    if ($host === '' && $user === '' && $password === '') {
        return null;
    }
    if ($host === '' || $user === '' || $password === '') {
        fwrite(STDERR, "DB_LIVE_CONFIG_INCOMPLETE\n");
        exit(1);
    }
    return [
        'host' => $host,
        'port' => envValue('ACE_DB_LIVE_PORT') !== '' ? envValue('ACE_DB_LIVE_PORT') : '3306',
        'user' => $user,
        'pwd' => $password,
    ];
}

function databaseConfigFromPhpProject(): array
{
    $configPath = getenv('ACE_INSTALL_DB_PRIVILEGE_CONFIG') ?: 'D:\\Desktop\\0\\ACE网络验证\\config\\local.php';
    if (!is_file($configPath)) {
        fwrite(STDERR, "CONFIG_NOT_FOUND {$configPath}\n");
        exit(1);
    }
    require $configPath;
    if (!isset($dbconfig) || !is_array($dbconfig)) {
        fwrite(STDERR, "DB_CONFIG_MISSING\n");
        exit(1);
    }
    return $dbconfig;
}

$databaseConfig = databaseConfigFromEnvironment() ?? databaseConfigFromPhpProject();
$smoke = new InstallDatabasePrivilegeSmoke($databaseConfig);
exit($smoke->run());
