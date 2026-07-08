<?php
declare(strict_types=1);

final class RemainingLiveSmokeGate
{
    private const prodHealthUrl = 'https://example.com/health';
    private const prodPhpHealthUrl = 'https://example.com/api/v1/index.php?route=/health';
    private const demoHealthUrl = 'https://demo.example.com/health';

    public function run(): int
    {
        $results = [
            $this->healthCheck('prod', $this->prodHealthUrl(), $this->expectedRuntime('ACE_REMAINING_PROD_RUNTIME', 'skip')),
            $this->healthCheck('demo', $this->demoHealthUrl(), $this->expectedRuntime('ACE_REMAINING_DEMO_RUNTIME', 'skip')),
            $this->scriptCheck('installDatabasePrivilegeSmoke.php'),
            $this->scriptCheck('installLiveDatabaseSmoke.php'),
            $this->scriptCheck('cloudStorageProviderCredentialSmoke.php'),
        ];

        foreach ($results as $result) {
            echo $result['line'] . "\n";
        }

        $failed = array_values(array_filter($results, static fn(array $result): bool => $result['status'] === 'failed'));
        if ($failed !== []) {
            echo 'REMAINING_LIVE_SMOKE_GATE_FAILED items=' . implode(',', array_column($failed, 'name')) . "\n";
            return 1;
        }

        $blocked = array_values(array_filter($results, static fn(array $result): bool => $result['status'] === 'blocked'));
        if ($blocked !== []) {
            echo 'REMAINING_LIVE_SMOKE_BLOCKED items=' . implode(',', array_column($blocked, 'name')) . "\n";
            return 0;
        }

        echo "REMAINING_LIVE_SMOKE_READY\n";
        return 0;
    }

    private function prodHealthUrl(): string
    {
        $runtime = $this->expectedRuntime('ACE_REMAINING_PROD_RUNTIME', 'skip');
        $envName = $runtime === 'php' ? 'ACE_REMAINING_PROD_PHP_HEALTH_URL' : 'ACE_REMAINING_PROD_RUST_HEALTH_URL';
        $default = $runtime === 'php' ? self::prodPhpHealthUrl : self::prodHealthUrl;
        return $this->envOrDefault($envName, $default);
    }

    private function demoHealthUrl(): string
    {
        return $this->envOrDefault('ACE_REMAINING_DEMO_RUST_HEALTH_URL', self::demoHealthUrl);
    }

    private function envOrDefault(string $envName, string $default): string
    {
        $value = trim((string)(getenv($envName) ?: ''));
        return $value === '' ? $default : $value;
    }

    private function expectedRuntime(string $envName, string $default): string
    {
        $value = strtolower(trim((string)(getenv($envName) ?: '')));
        if ($value === '') {
            return $default;
        }
        if (!in_array($value, ['php', 'rust', 'skip'], true)) {
            fwrite(STDERR, "REMAINING_GATE_BAD_RUNTIME env={$envName} value={$value}\n");
            exit(1);
        }
        return $value;
    }

    private function healthCheck(string $name, string $url, string $expectedRuntime): array
    {
        if ($expectedRuntime === 'skip') {
            return [
                'name' => "{$name}Health",
                'status' => 'passed',
                'line' => "REMAINING_GATE_HEALTH_SKIPPED target={$name}",
            ];
        }
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'ignore_errors' => true,
                'timeout' => 10,
                'header' => "Accept: application/json\r\n",
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);
        $body = @file_get_contents($url, false, $context);
        $headers = $http_response_header ?? [];
        $status = $this->httpStatus($headers);
        $contentType = $this->contentType($headers);
        $payload = is_string($body) ? json_decode($body, true) : null;
        $runtime = is_array($payload) ? (string)($payload['data']['runtime'] ?? '') : '';
        $serviceStatus = is_array($payload) ? (string)($payload['data']['status'] ?? '') : '';
        $isExpectedRuntime = $expectedRuntime === 'rust'
            ? $runtime === 'rust'
            : $runtime === '' && $serviceStatus === 'ok';
        if ($status === 200 && str_starts_with($contentType, 'application/json') && $isExpectedRuntime) {
            return [
                'name' => "{$name}Health",
                'status' => 'passed',
                'line' => "REMAINING_GATE_HEALTH_OK target={$name} runtime={$expectedRuntime}",
            ];
        }
        return [
            'name' => "{$name}Health",
            'status' => 'failed',
            'line' => "REMAINING_GATE_HEALTH_FAILED target={$name} expectedRuntime={$expectedRuntime} httpStatus={$status} contentType={$contentType} runtime={$runtime} status={$serviceStatus}",
        ];
    }

    private function scriptCheck(string $scriptName): array
    {
        $scriptPath = __DIR__ . DIRECTORY_SEPARATOR . $scriptName;
        $result = $this->runScript($scriptPath);
        $output = trim($result['output']);
        if ($result['exitCode'] !== 0) {
            return [
                'name' => $this->scriptName($scriptName),
                'status' => 'failed',
                'line' => "REMAINING_GATE_SCRIPT_FAILED script={$scriptName} exitCode={$result['exitCode']} output=" . $this->compactOutput($output),
            ];
        }
        if (str_contains($output, 'LIVE_SMOKE_BLOCKED')) {
            return [
                'name' => $this->scriptName($scriptName),
                'status' => 'blocked',
                'line' => "REMAINING_GATE_SCRIPT_BLOCKED script={$scriptName} output=" . $this->compactOutput($output),
            ];
        }
        return [
            'name' => $this->scriptName($scriptName),
            'status' => 'passed',
            'line' => "REMAINING_GATE_SCRIPT_OK script={$scriptName} output=" . $this->compactOutput($output),
        ];
    }

    private function runScript(string $scriptPath): array
    {
        $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($scriptPath);
        $descriptorSpec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = proc_open($command, $descriptorSpec, $pipes, __DIR__);
        if (!is_resource($process)) {
            return ['exitCode' => 1, 'output' => 'proc_open failed'];
        }
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        return [
            'exitCode' => $exitCode,
            'output' => trim((string)$stdout . "\n" . (string)$stderr),
        ];
    }

    private function scriptName(string $scriptName): string
    {
        return preg_replace('/\\.php$/', '', $scriptName) ?? $scriptName;
    }

    private function compactOutput(string $output): string
    {
        $line = preg_replace('/\s+/', ' ', $output) ?? '';
        return trim($line);
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
        foreach ($headers as $header) {
            $parts = explode(':', (string)$header, 2);
            if (count($parts) === 2 && strcasecmp(trim($parts[0]), 'Content-Type') === 0) {
                return strtolower(trim((string)strtok(trim($parts[1]), ';')));
            }
        }
        return '';
    }
}

$gate = new RemainingLiveSmokeGate();
exit($gate->run());
