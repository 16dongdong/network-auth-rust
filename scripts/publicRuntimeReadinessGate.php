<?php
declare(strict_types=1);

final class PublicRuntimeReadinessGate
{
    private const TARGETS = [
        'prod' => [
            'baseUrl' => 'https://example.com',
            'phpHealthUrl' => 'https://example.com/api/v1/index.php?route=/health',
            'rustHealthUrl' => 'https://example.com/health',
            'defaultRuntime' => 'skip',
            'runtimeEnv' => 'ACE_PUBLIC_PROD_RUNTIME',
        ],
        'demo' => [
            'baseUrl' => 'https://demo.example.com',
            'phpHealthUrl' => 'https://demo.example.com/api/v1/index.php?route=/health',
            'rustHealthUrl' => 'https://demo.example.com/health',
            'defaultRuntime' => 'skip',
            'runtimeEnv' => 'ACE_PUBLIC_DEMO_RUNTIME',
        ],
    ];

    private const STATIC_ASSETS = [
        '/assets/layui/layui.js' => 'layui.define',
        '/frontend/admin-console/js/app.js' => '(function (app)',
        '/frontend/admin-console/css/app.css' => '.auth-admin',
    ];

    public function run(array $arguments): int
    {
        if (in_array('--help', $arguments, true) || in_array('-h', $arguments, true)) {
            $this->printHelp();
            return 0;
        }

        $targetNames = $this->targetNames($arguments);
        $runtimeOverrides = $this->runtimeOverrides($arguments);
        $this->assertRuntimeOverridesTargetSelected($targetNames, $runtimeOverrides);
        $results = [];
        foreach ($targetNames as $targetName) {
            $target = $this->targetConfig($targetName);
            $expectedRuntime = $this->expectedRuntime($targetName, $target, $runtimeOverrides);
            if ($expectedRuntime === 'skip') {
                $results[] = $this->passed($targetName, 'runtime', "PUBLIC_RUNTIME_TARGET_SKIPPED target={$targetName}");
                continue;
            }
            array_push(
                $results,
                $this->checkHealth($targetName, $target, $expectedRuntime),
                $this->checkAdminLogin($targetName, $target),
                $this->checkAdminConsoleRedirect($targetName, $target),
                $this->checkRemoteApiUnsigned($targetName, $target),
                ...$this->checkStaticAssets($targetName, $target),
            );
        }

        foreach ($results as $result) {
            echo $result['line'] . "\n";
        }

        $failed = array_values(array_filter($results, static fn(array $result): bool => !$result['ok']));
        if ($failed !== []) {
            fwrite(STDERR, 'PUBLIC_RUNTIME_READINESS_FAILED checks=' . implode(',', array_column($failed, 'name')) . "\n");
            return 1;
        }

        echo 'PUBLIC_RUNTIME_READINESS_OK targets=' . count($targetNames) . ' checks=' . count($results) . "\n";
        return 0;
    }

    private function printHelp(): void
    {
        echo "Usage: php scripts/publicRuntimeReadinessGate.php [--target=prod|demo] [--expect-runtime=target:php|rust|skip]\n";
        echo "Checks public PHP/Rust runtime, admin entries, unsigned remote API, and core static assets.\n";
        echo "Set ACE_PUBLIC_PROD_RUNTIME or ACE_PUBLIC_DEMO_RUNTIME to php, rust, or skip when needed. Public defaults are skip.\n";
        echo "--expect-runtime takes precedence over environment defaults, for example --expect-runtime=prod:rust.\n";
        echo "Test harnesses may override ACE_PUBLIC_<TARGET>_BASE_URL, PHP_HEALTH_URL, and RUST_HEALTH_URL.\n";
    }

    private function targetNames(array $arguments): array
    {
        $targets = [];
        foreach ($arguments as $argument) {
            if (!str_starts_with($argument, '--target=')) {
                continue;
            }
            $targetName = strtolower(trim(substr($argument, strlen('--target='))));
            if (!array_key_exists($targetName, self::TARGETS)) {
                fwrite(STDERR, "PUBLIC_RUNTIME_BAD_TARGET target={$targetName}\n");
                exit(1);
            }
            $targets[] = $targetName;
        }
        return $targets === [] ? array_keys(self::TARGETS) : array_values(array_unique($targets));
    }

    private function runtimeOverrides(array $arguments): array
    {
        $overrides = [];
        foreach ($arguments as $argument) {
            if (!str_starts_with($argument, '--expect-runtime=')) {
                continue;
            }
            $value = strtolower(trim(substr($argument, strlen('--expect-runtime='))));
            $parts = explode(':', $value, 2);
            if (count($parts) !== 2 || !array_key_exists($parts[0], self::TARGETS) || !in_array($parts[1], ['php', 'rust', 'skip'], true)) {
                fwrite(STDERR, "PUBLIC_RUNTIME_BAD_EXPECT_RUNTIME value={$value}\n");
                exit(1);
            }
            $overrides[$parts[0]] = $parts[1];
        }
        return $overrides;
    }

    private function assertRuntimeOverridesTargetSelected(array $targetNames, array $runtimeOverrides): void
    {
        $unusedTargets = array_values(array_diff(array_keys($runtimeOverrides), $targetNames));
        if ($unusedTargets === []) {
            return;
        }
        fwrite(STDERR, 'PUBLIC_RUNTIME_UNUSED_EXPECT_RUNTIME targets=' . implode(',', $unusedTargets) . ' selected=' . implode(',', $targetNames) . "\n");
        exit(1);
    }

    private function expectedRuntime(string $targetName, array $target, array $runtimeOverrides): string
    {
        if (array_key_exists($targetName, $runtimeOverrides)) {
            return $runtimeOverrides[$targetName];
        }
        $value = strtolower(trim((string)(getenv($target['runtimeEnv']) ?: '')));
        $runtime = $value === '' ? (string)$target['defaultRuntime'] : $value;
        if (!in_array($runtime, ['php', 'rust', 'skip'], true)) {
            fwrite(STDERR, "PUBLIC_RUNTIME_BAD_EXPECTED_RUNTIME env={$target['runtimeEnv']} value={$runtime}\n");
            exit(1);
        }
        return $runtime;
    }

    private function targetConfig(string $targetName): array
    {
        $target = self::TARGETS[$targetName];
        $envPrefix = 'ACE_PUBLIC_' . strtoupper($targetName);
        return [
            'baseUrl' => $this->envOrDefault("{$envPrefix}_BASE_URL", (string)$target['baseUrl']),
            'phpHealthUrl' => $this->envOrDefault("{$envPrefix}_PHP_HEALTH_URL", (string)$target['phpHealthUrl']),
            'rustHealthUrl' => $this->envOrDefault("{$envPrefix}_RUST_HEALTH_URL", (string)$target['rustHealthUrl']),
            'defaultRuntime' => $target['defaultRuntime'],
            'runtimeEnv' => $target['runtimeEnv'],
        ];
    }

    private function envOrDefault(string $name, string $default): string
    {
        $value = trim((string)(getenv($name) ?: ''));
        return $value === '' ? $default : $value;
    }

    private function checkHealth(string $targetName, array $target, string $expectedRuntime): array
    {
        $healthUrl = $expectedRuntime === 'rust' ? $target['rustHealthUrl'] : $target['phpHealthUrl'];
        $response = $this->request('GET', $healthUrl, ['Accept: application/json']);
        $payload = json_decode($response['body'], true);
        $runtime = is_array($payload) ? (string)($payload['data']['runtime'] ?? '') : '';
        $serviceStatus = is_array($payload) ? (string)($payload['data']['status'] ?? '') : '';
        $runtimeMatches = $expectedRuntime === 'rust'
            ? $runtime === 'rust'
            : $runtime === '' && $serviceStatus === 'ok';
        if ($response['status'] === 200 && $response['contentType'] === 'application/json' && $runtimeMatches) {
            return $this->passed($targetName, 'health', "PUBLIC_RUNTIME_HEALTH_OK target={$targetName} runtime={$expectedRuntime}");
        }
        return $this->failed($targetName, 'health', "PUBLIC_RUNTIME_HEALTH_FAILED target={$targetName} expectedRuntime={$expectedRuntime} httpStatus={$response['status']} contentType={$response['contentType']} runtime={$runtime} status={$serviceStatus}");
    }

    private function checkAdminLogin(string $targetName, array $target): array
    {
        $response = $this->request('GET', $this->url($target, '/admin/login/'), ['Accept: text/html']);
        $hasLoginForm = str_contains($response['body'], 'name="username"') && str_contains($response['body'], 'name="password"');
        if ($response['status'] === 200 && $response['contentType'] === 'text/html' && $hasLoginForm) {
            return $this->passed($targetName, 'adminLogin', "PUBLIC_RUNTIME_ADMIN_LOGIN_OK target={$targetName}");
        }
        return $this->failed($targetName, 'adminLogin', "PUBLIC_RUNTIME_ADMIN_LOGIN_FAILED target={$targetName} httpStatus={$response['status']} contentType={$response['contentType']}");
    }

    private function checkAdminConsoleRedirect(string $targetName, array $target): array
    {
        $response = $this->request('GET', $this->url($target, '/admin/console/'), ['Accept: text/html']);
        $locationPath = $this->locationPath($response['location']);
        if ($response['status'] === 302 && in_array($locationPath, ['/admin/login/', '/admin/login'], true)) {
            return $this->passed($targetName, 'adminConsole', "PUBLIC_RUNTIME_ADMIN_CONSOLE_OK target={$targetName}");
        }
        return $this->failed($targetName, 'adminConsole', "PUBLIC_RUNTIME_ADMIN_CONSOLE_FAILED target={$targetName} httpStatus={$response['status']} location={$response['location']}");
    }

    private function checkRemoteApiUnsigned(string $targetName, array $target): array
    {
        $response = $this->request(
            'POST',
            $this->url($target, '/api/v1/index.php?route=%2Fremote%2Fcloud-storage%2Fsummary'),
            ['Accept: application/json', 'Content-Type: application/json'],
            '{}',
        );
        $payload = json_decode($response['body'], true);
        $error = is_array($payload) ? (string)($payload['error'] ?? '') : '';
        if ($response['status'] === 401 && $response['contentType'] === 'application/json' && $error === 'REMOTE_API_HEADER_MISSING') {
            return $this->passed($targetName, 'remoteApiUnsigned', "PUBLIC_RUNTIME_REMOTE_API_OK target={$targetName}");
        }
        return $this->failed($targetName, 'remoteApiUnsigned', "PUBLIC_RUNTIME_REMOTE_API_FAILED target={$targetName} httpStatus={$response['status']} contentType={$response['contentType']} error={$error}");
    }

    private function checkStaticAssets(string $targetName, array $target): array
    {
        $results = [];
        foreach (self::STATIC_ASSETS as $path => $marker) {
            $response = $this->request('GET', $this->url($target, $path), ['Accept: */*']);
            $assetName = trim(str_replace('/', '_', $path), '_');
            if ($response['status'] === 200 && str_contains($response['body'], $marker)) {
                $results[] = $this->passed($targetName, $assetName, "PUBLIC_RUNTIME_STATIC_ASSET_OK target={$targetName} path={$path}");
                continue;
            }
            $results[] = $this->failed($targetName, $assetName, "PUBLIC_RUNTIME_STATIC_ASSET_FAILED target={$targetName} path={$path} httpStatus={$response['status']}");
        }
        return $results;
    }

    private function request(string $method, string $url, array $headers, string $body = ''): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'ignore_errors' => true,
                'timeout' => 15,
                'follow_location' => 0,
                'header' => implode("\r\n", $headers),
                'content' => $body,
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);
        $responseBody = @file_get_contents($url, false, $context);
        $responseHeaders = $http_response_header ?? [];
        return [
            'status' => $this->httpStatus($responseHeaders),
            'contentType' => $this->contentType($responseHeaders),
            'location' => $this->headerValue($responseHeaders, 'Location'),
            'body' => is_string($responseBody) ? $responseBody : '',
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

    private function contentType(array $headers): string
    {
        $contentType = $this->headerValue($headers, 'Content-Type');
        return strtolower(trim((string)strtok($contentType, ';')));
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

    private function locationPath(string $location): string
    {
        if ($location === '') {
            return '';
        }
        $path = parse_url($location, PHP_URL_PATH);
        return is_string($path) ? $path : $location;
    }

    private function url(array $target, string $path): string
    {
        return rtrim((string)$target['baseUrl'], '/') . $path;
    }

    private function passed(string $targetName, string $checkName, string $line): array
    {
        return ['ok' => true, 'name' => "{$targetName}:{$checkName}", 'line' => $line];
    }

    private function failed(string $targetName, string $checkName, string $line): array
    {
        return ['ok' => false, 'name' => "{$targetName}:{$checkName}", 'line' => $line];
    }
}

exit((new PublicRuntimeReadinessGate())->run(array_slice($_SERVER['argv'] ?? [], 1)));
