<?php
declare(strict_types=1);

final class InstallReadonlyParityCheck
{
    public function __construct(
        private readonly string $phpBaseUrl,
        private readonly string $rustBaseUrl
    ) {
    }

    public function run(): int
    {
        $phpResult = $this->runTarget('php', $this->phpBaseUrl);
        $rustResult = $this->runTarget('rust', $this->rustBaseUrl);
        $this->printResult('php', $phpResult);
        $this->printResult('rust', $rustResult);
        $diffs = $this->diff($phpResult, $rustResult, 'installReadonly');
        if ($diffs !== []) {
            foreach ($diffs as $diff) {
                fwrite(STDERR, "DIFF {$diff}\n");
            }
            return 1;
        }
        echo "PARITY_OK install readonly flows\n";
        return 0;
    }

    private function runTarget(string $name, string $baseUrl): array
    {
        $target = ['name' => $name, 'baseUrl' => rtrim($baseUrl, '/')];
        return [
            'steps' => [
                'env' => $this->normalizePage($this->httpRaw($target, 'GET', '/install/')),
                'database' => $this->normalizePage($this->httpRaw($target, 'GET', '/install/?step=database')),
                'adminWithoutDb' => $this->normalizePage($this->httpRaw($target, 'GET', '/install/?step=admin')),
                'doneWithoutResult' => $this->normalizePage($this->httpRaw($target, 'GET', '/install/?step=done')),
                'invalidStep' => $this->normalizePage($this->httpRaw($target, 'GET', '/install/?step=unknown')),
                'legacyRedirect' => $this->normalizeRedirect($this->httpRaw($target, 'GET', '/install/index.php?step=database')),
                'postSaveNoCsrf' => $this->normalizePage($this->httpRaw(
                    $target,
                    'POST',
                    '/install/?step=database',
                    http_build_query([
                        'action' => 'save_database',
                        'host' => 'bad.example.test',
                        'port' => '3307',
                        'dbname' => 'bad_db',
                        'user' => 'bad_user',
                        'pwd' => 'bad_pwd',
                    ], '', '&', PHP_QUERY_RFC3986)
                )),
                'postInstallNoCsrf' => $this->normalizePage($this->httpRaw(
                    $target,
                    'POST',
                    '/install/?step=admin',
                    http_build_query([
                        'action' => 'install_system',
                        'username' => 'bad_admin',
                        'password' => 'one',
                        'confirm_password' => 'two',
                    ], '', '&', PHP_QUERY_RFC3986)
                )),
            ],
        ];
    }

    private function normalizePage(array $response): array
    {
        $body = (string)$response['body'];
        return [
            'httpStatus' => (int)$response['httpStatus'],
            'contentType' => $this->contentTypeBase($this->headerValue($response['headers'], 'Content-Type')),
            'xFrameOptions' => $this->headerValue($response['headers'], 'X-Frame-Options'),
            'xContentTypeOptions' => $this->headerValue($response['headers'], 'X-Content-Type-Options'),
            'referrerPolicy' => $this->headerValue($response['headers'], 'Referrer-Policy'),
            'title' => $this->firstMatch('/<title>(.*?)<\/title>/su', $body),
            'h1' => $this->firstMatch('/<h1>(.*?)<\/h1>/su', $body),
            'activeStep' => $this->firstMatch('/<div class="step-item active"><span class="step-index">\d+<\/span><span>(.*?)<\/span><\/div>/su', $body),
            'mascotImage' => $this->firstMatch('/<img src="([^"]+)" alt="" class="mascot-img"/su', $body),
            'hasDatabaseForm' => str_contains($body, 'name="action" value="save_database"'),
            'hasAdminForm' => str_contains($body, 'name="action" value="install_system"'),
            'hasDoneLinks' => str_contains($body, 'href="/admin/login/"') && str_contains($body, 'href="/admin/console/"'),
            'hasCsrf' => preg_match('/name="csrf_token" value="[a-f0-9]{64}"/', $body) === 1,
            'errorState' => str_contains($body, '请求验证失败，请刷新页面重试。') ? 'csrf' : 'none',
            'dbDefaults' => $this->dbDefaults($body),
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

    private function dbDefaults(string $body): array
    {
        if (!str_contains($body, 'name="action" value="save_database"')) {
            return [];
        }
        return [
            'host' => $this->inputValue($body, 'host'),
            'port' => $this->inputValue($body, 'port'),
            'dbname' => $this->inputValue($body, 'dbname'),
            'user' => $this->inputValue($body, 'user'),
            'createDatabaseChecked' => preg_match('/name="create_database" value="1"\s+checked/', $body) === 1,
        ];
    }

    private function inputValue(string $body, string $name): string
    {
        return html_entity_decode($this->firstMatch('/name="' . preg_quote($name, '/') . '" value="([^"]*)"/su', $body), ENT_QUOTES, 'UTF-8');
    }

    private function httpRaw(array $target, string $method, string $path, string $body = ''): array
    {
        $headers = [
            'Accept: text/html,application/xhtml+xml',
        ];
        if ($method === 'POST') {
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
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
        return [
            'httpStatus' => $this->httpStatus($http_response_header ?? []),
            'headers' => $http_response_header ?? [],
            'body' => is_string($raw) ? $raw : '',
        ];
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

$check = new InstallReadonlyParityCheck(
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
