<?php
declare(strict_types=1);

define('IN_CRONLITE', true);
require 'D:\\Desktop\\0\\ACE网络验证\\config\\local.php';

final class InstallDatabaseStepParityCheck
{
    private array $databaseConfig;

    public function __construct(
        private readonly string $phpBaseUrl,
        private readonly string $rustBaseUrl,
        array $databaseConfig
    ) {
        $this->databaseConfig = $databaseConfig;
    }

    public function run(): int
    {
        $phpResult = $this->runTarget('php', $this->phpBaseUrl);
        $rustResult = $this->runTarget('rust', $this->rustBaseUrl);
        $this->printResult('php', $phpResult);
        $this->printResult('rust', $rustResult);
        $diffs = $this->diff($phpResult, $rustResult, 'installDatabaseStep');
        if ($diffs !== []) {
            foreach ($diffs as $diff) {
                fwrite(STDERR, "DIFF {$diff}\n");
            }
            return 1;
        }
        echo "PARITY_OK install database step valid submit\n";
        return 0;
    }

    private function runTarget(string $name, string $baseUrl): array
    {
        $target = ['name' => $name, 'baseUrl' => rtrim($baseUrl, '/')];
        $jar = [];
        $databasePage = $this->httpRaw($target, $jar, 'GET', '/install/?step=database');
        $csrfToken = $this->firstMatch('/name="csrf_token" value="([a-f0-9]{64})"/su', (string)$databasePage['body']);
        $postBody = http_build_query([
            'action' => 'save_database',
            'csrf_token' => $csrfToken,
            'host' => (string)$this->databaseConfig['host'],
            'port' => (string)$this->databaseConfig['port'],
            'dbname' => (string)$this->databaseConfig['dbname'],
            'user' => (string)$this->databaseConfig['user'],
            'pwd' => (string)$this->databaseConfig['pwd'],
        ], '', '&', PHP_QUERY_RFC3986);
        $saveResponse = $this->httpRaw($target, $jar, 'POST', '/install/?step=database', $postBody);
        $adminPage = $this->httpRaw($target, $jar, 'GET', '/install/?step=admin');
        $adminCsrfToken = $this->firstMatch('/name="csrf_token" value="([a-f0-9]{64})"/su', (string)$adminPage['body']);
        $adminPostBody = http_build_query([
            'action' => 'install_system',
            'csrf_token' => $adminCsrfToken,
            'username' => 'admin',
            'password' => 'install-password-a',
            'confirm_password' => 'install-password-b',
        ], '', '&', PHP_QUERY_RFC3986);
        $adminErrorPage = $this->httpRaw($target, $jar, 'POST', '/install/?step=admin', $adminPostBody);
        return [
            'databasePage' => $this->normalizePage($databasePage),
            'saveResponse' => $this->normalizeRedirect($saveResponse),
            'adminPage' => $this->normalizePage($adminPage),
            'adminMismatchPage' => $this->normalizePage($adminErrorPage),
        ];
    }

    private function normalizePage(array $response): array
    {
        $body = (string)$response['body'];
        return [
            'httpStatus' => (int)$response['httpStatus'],
            'contentType' => $this->contentTypeBase($this->headerValue($response['headers'], 'Content-Type')),
            'title' => $this->firstMatch('/<title>(.*?)<\/title>/su', $body),
            'h1' => $this->firstMatch('/<h1>(.*?)<\/h1>/su', $body),
            'activeStep' => $this->firstMatch('/<div class="step-item active"><span class="step-index">\d+<\/span><span>(.*?)<\/span><\/div>/su', $body),
            'hasDatabaseForm' => str_contains($body, 'name="action" value="save_database"'),
            'hasAdminForm' => str_contains($body, 'name="action" value="install_system"'),
            'hasCsrf' => preg_match('/name="csrf_token" value="[a-f0-9]{64}"/', $body) === 1,
            'errorState' => str_contains($body, '请求验证失败，请刷新页面重试。') ? 'csrf' : 'none',
            'errorText' => $this->firstMatch('/<div class="error-box">(.*?)<\/div>/su', $body),
        ];
    }

    private function normalizeRedirect(array $response): array
    {
        return [
            'httpStatus' => (int)$response['httpStatus'],
            'contentType' => $this->contentTypeBase($this->headerValue($response['headers'], 'Content-Type')),
            'location' => $this->headerValue($response['headers'], 'Location'),
        ];
    }

    private function httpRaw(array $target, array &$jar, string $method, string $path, string $body = ''): array
    {
        $headers = ['Accept: text/html,application/xhtml+xml'];
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
                'timeout' => 10,
                'follow_location' => 0,
            ],
        ]);
        $raw = @file_get_contents($target['baseUrl'] . $path, false, $context);
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
            if ($name !== '') {
                if ($this->cookieExpired($cookie, $value)) {
                    unset($jar[$name]);
                    continue;
                }
                $jar[$name] = $value;
            }
        }
    }

    private function cookieExpired(string $cookie, string $value): bool
    {
        if ($value === '' || $value === 'deleted') {
            return true;
        }
        foreach (explode(';', $cookie) as $attribute) {
            $attribute = trim($attribute);
            if (strcasecmp($attribute, 'Max-Age=0') === 0) {
                return true;
            }
            if (stripos($attribute, 'Expires=') === 0) {
                $timestamp = strtotime(substr($attribute, strlen('Expires=')));
                return is_int($timestamp) && $timestamp <= time();
            }
        }
        return false;
    }

    private function firstMatch(string $pattern, string $body): string
    {
        if (preg_match($pattern, $body, $matches) !== 1) {
            return '';
        }
        return trim(html_entity_decode(strip_tags((string)$matches[1]), ENT_QUOTES, 'UTF-8'));
    }

    private function contentTypeBase(string $value): string
    {
        return strtolower(trim(strtok($value, ';') ?: $value));
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

    private function httpStatus(array $headers): int
    {
        foreach ($headers as $header) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', (string)$header, $matches) === 1) {
                return (int)$matches[1];
            }
        }
        return 0;
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
}

$check = new InstallDatabaseStepParityCheck(
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080',
    $dbconfig
);
exit($check->run());
