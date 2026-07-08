<?php
declare(strict_types=1);

final class ProdCutoverSequenceGateSelfTest
{
    private const SCENARIOS = [
        'pre' => [['--pre-cutover'], 0, 'PROD_CUTOVER_SEQUENCE_PRE_OK'],
        'post' => [['--post-cutover'], 0, 'PROD_CUTOVER_SEQUENCE_POST_OK'],
        'post_bad_runtime' => [['--post-cutover'], 1, 'PROD_CUTOVER_SEQUENCE_FAILED'],
        'pre_bad_runtime' => [['--pre-cutover'], 1, 'PROD_CUTOVER_SEQUENCE_FAILED'],
    ];

    private readonly string $projectRoot;
    private readonly string $workRoot;

    public function __construct()
    {
        $this->projectRoot = dirname(__DIR__);
        $this->workRoot = $this->projectRoot . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'tmp'
            . DIRECTORY_SEPARATOR . 'prod-cutover-sequence-self-test-' . bin2hex(random_bytes(4));
    }

    public function run(): int
    {
        @mkdir($this->workRoot, 0777, true);
        $routerPath = $this->writeRouter();
        try {
            foreach (self::SCENARIOS as $scenario => [$arguments, $expectedExitCode, $expectedMarker]) {
                $result = $this->runScenario($scenario, $routerPath, $arguments);
                if ($result['exitCode'] !== $expectedExitCode || !str_contains($result['output'], $expectedMarker)) {
                    fwrite(STDERR, "PROD_CUTOVER_SEQUENCE_SELF_TEST_FAILED scenario={$scenario} exitCode={$result['exitCode']} output={$this->compactOutput($result['output'])}\n");
                    return 1;
                }
                echo "PROD_CUTOVER_SEQUENCE_SELF_TEST_SCENARIO_OK scenario={$scenario}\n";
            }
            echo "PROD_CUTOVER_SEQUENCE_SELF_TEST_OK scenarios=" . count(self::SCENARIOS) . "\n";
            return 0;
        } finally {
            $this->removeTree($this->workRoot);
        }
    }

    private function writeRouter(): string
    {
        $routerPath = $this->workRoot . DIRECTORY_SEPARATOR . 'router.php';
        file_put_contents($routerPath, <<<'PHP'
<?php
declare(strict_types=1);

$scenario = getenv('PROD_CUTOVER_FAKE_SCENARIO') ?: 'pre';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

function jsonResponse(int $statusCode, array $payload): void
{
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
}

if ($path === '/__ready') {
    header('Content-Type: text/plain');
    echo 'ready';
    return;
}

if ($path === '/prod/php-health') {
    $data = ['status' => 'ok'];
    if ($scenario === 'pre_bad_runtime') {
        $data['runtime'] = 'rust';
    }
    jsonResponse(200, ['code' => 0, 'data' => $data]);
    return;
}

if ($path === '/prod/rust-health') {
    $runtime = in_array($scenario, ['post'], true) ? 'rust' : 'php';
    jsonResponse(200, ['code' => 0, 'data' => ['status' => 'ok', 'runtime' => $runtime]]);
    return;
}

if ($path === '/demo/php-health') {
    jsonResponse(200, ['code' => 0, 'data' => ['status' => 'ok']]);
    return;
}

if ($path === '/demo/rust-health') {
    jsonResponse(200, ['code' => 0, 'data' => ['status' => 'ok', 'runtime' => 'rust']]);
    return;
}

if ($path === '/admin/login/') {
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
    echo '<form><input name="username"><input name="password"></form>';
    return;
}

if ($path === '/admin/console/') {
    http_response_code(302);
    header('Location: /admin/login/');
    return;
}

if ($path === '/api/v1/index.php') {
    jsonResponse(401, ['error' => 'REMOTE_API_HEADER_MISSING']);
    return;
}

if ($path === '/assets/layui/layui.js') {
    http_response_code(200);
    header('Content-Type: application/javascript');
    echo 'layui.define(function(){})';
    return;
}

if ($path === '/frontend/admin-console/js/app.js') {
    http_response_code(200);
    header('Content-Type: application/javascript');
    echo '(function (app) {})(window.app || {})';
    return;
}

if ($path === '/frontend/admin-console/css/app.css') {
    http_response_code(200);
    header('Content-Type: text/css');
    echo '.auth-admin { display:block; }';
    return;
}

http_response_code(404);
header('Content-Type: text/plain');
echo 'not found';
PHP);
        return $routerPath;
    }

    private function runScenario(string $scenario, string $routerPath, array $arguments): array
    {
        $port = $this->freePort();
        $baseUrl = "http://127.0.0.1:{$port}";
        $server = $this->startServer($scenario, $port, $routerPath);
        try {
            $this->waitUntilReady($baseUrl);
            return $this->runGate($baseUrl, $arguments);
        } finally {
            $this->stopServer($server);
        }
    }

    private function startServer(string $scenario, int $port, string $routerPath): mixed
    {
        $environment = getenv();
        $environment['PROD_CUTOVER_FAKE_SCENARIO'] = $scenario;
        $process = proc_open(
            [PHP_BINARY, '-S', "127.0.0.1:{$port}", '-t', $this->workRoot, $routerPath],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $this->workRoot,
            $environment,
        );
        if (!is_resource($process)) {
            throw new RuntimeException('failed to start fake prod cutover server');
        }
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        return $process;
    }

    private function runGate(string $baseUrl, array $arguments): array
    {
        $environment = getenv();
        $environment['ACE_PUBLIC_PROD_BASE_URL'] = $baseUrl;
        $environment['ACE_PUBLIC_PROD_PHP_HEALTH_URL'] = $baseUrl . '/prod/php-health';
        $environment['ACE_PUBLIC_PROD_RUST_HEALTH_URL'] = $baseUrl . '/prod/rust-health';
        $environment['ACE_PUBLIC_DEMO_BASE_URL'] = $baseUrl;
        $environment['ACE_PUBLIC_DEMO_PHP_HEALTH_URL'] = $baseUrl . '/demo/php-health';
        $environment['ACE_PUBLIC_DEMO_RUST_HEALTH_URL'] = $baseUrl . '/demo/rust-health';

        $process = proc_open(
            array_merge([PHP_BINARY, __DIR__ . DIRECTORY_SEPARATOR . 'prodCutoverSequenceGate.php'], $arguments),
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $this->projectRoot,
            $environment,
        );
        if (!is_resource($process)) {
            throw new RuntimeException('failed to run prod cutover sequence gate');
        }
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        return [
            'exitCode' => proc_close($process),
            'output' => trim((string)$stdout . "\n" . (string)$stderr),
        ];
    }

    private function waitUntilReady(string $baseUrl): void
    {
        $deadline = microtime(true) + 5;
        while (microtime(true) < $deadline) {
            $body = @file_get_contents($baseUrl . '/__ready');
            if ($body === 'ready') {
                return;
            }
            usleep(100000);
        }
        throw new RuntimeException('fake prod cutover server did not become ready');
    }

    private function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
        if (!is_resource($socket)) {
            throw new RuntimeException("failed to allocate port: {$errorCode} {$errorMessage}");
        }
        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        $port = (int)substr(strrchr((string)$name, ':'), 1);
        if ($port <= 0) {
            throw new RuntimeException('failed to parse allocated port');
        }
        return $port;
    }

    private function stopServer(mixed $server): void
    {
        if (!is_resource($server)) {
            return;
        }
        proc_terminate($server);
        proc_close($server);
    }

    private function removeTree(string $path): void
    {
        for ($attempt = 0; $attempt < 20; $attempt++) {
            clearstatcache();
            if (!file_exists($path)) {
                return;
            }
            $this->removeTreeOnce($path);
            clearstatcache();
            if (!file_exists($path)) {
                return;
            }
            usleep(100000);
        }

        throw new RuntimeException("failed to remove temporary self-test directory: {$path}");
    }

    private function removeTreeOnce(string $path): void
    {
        if (!is_dir($path)) {
            @unlink($path);
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($iterator as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($path);
    }

    private function compactOutput(string $output): string
    {
        $normalized = preg_replace('/\s+/', ' ', trim($output)) ?? '';
        return strlen($normalized) <= 1400 ? $normalized : substr($normalized, 0, 700) . ' ... ' . substr($normalized, -700);
    }
}

exit((new ProdCutoverSequenceGateSelfTest())->run());
