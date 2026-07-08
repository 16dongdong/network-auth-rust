<?php
declare(strict_types=1);

define('IN_CRONLITE', true);
require 'D:\\Desktop\\0\\ACE网络验证\\config\\local.php';

final class InstallSystemStepRustSmoke
{
    private array $databaseConfig;

    public function __construct(private readonly string $baseUrl, array $databaseConfig)
    {
        $this->databaseConfig = $databaseConfig;
    }

    public function run(): int
    {
        $jar = [];
        $databasePage = $this->httpRaw($jar, 'GET', '/install/?step=database');
        $databaseCsrf = $this->csrfToken((string)$databasePage['body']);
        $databaseBody = http_build_query([
            'action' => 'save_database',
            'csrf_token' => $databaseCsrf,
            'host' => (string)$this->databaseConfig['host'],
            'port' => (string)$this->databaseConfig['port'],
            'dbname' => (string)$this->databaseConfig['dbname'],
            'user' => (string)$this->databaseConfig['user'],
            'pwd' => (string)$this->databaseConfig['pwd'],
        ], '', '&', PHP_QUERY_RFC3986);
        $saveResponse = $this->httpRaw($jar, 'POST', '/install/?step=database', $databaseBody);
        $adminPage = $this->httpRaw($jar, 'GET', '/install/?step=admin');
        $adminCsrf = $this->csrfToken((string)$adminPage['body']);
        $adminBody = http_build_query([
            'action' => 'install_system',
            'csrf_token' => $adminCsrf,
            'username' => 'admin',
            'password' => 'install-password-ok',
            'confirm_password' => 'install-password-ok',
        ], '', '&', PHP_QUERY_RFC3986);
        $installResponse = $this->httpRaw($jar, 'POST', '/install/?step=admin', $adminBody);
        $donePage = $this->httpRaw($jar, 'GET', '/install/?step=done');

        $summary = [
            'databaseStatus' => (int)$databasePage['httpStatus'],
            'saveStatus' => (int)$saveResponse['httpStatus'],
            'saveLocation' => $this->headerValue($saveResponse['headers'], 'Location'),
            'adminStatus' => (int)$adminPage['httpStatus'],
            'adminH1' => $this->firstMatch('/<h1>(.*?)<\/h1>/su', (string)$adminPage['body']),
            'installStatus' => (int)$installResponse['httpStatus'],
            'installLocation' => $this->headerValue($installResponse['headers'], 'Location'),
            'doneStatus' => (int)$donePage['httpStatus'],
            'doneH1' => $this->firstMatch('/<h1>(.*?)<\/h1>/su', (string)$donePage['body']),
            'hasConfigResult' => str_contains((string)$donePage['body'], '<strong>配置文件</strong>'),
            'hasAdminTokenResult' => str_contains((string)$donePage['body'], '<strong>后台维护令牌</strong>'),
        ];
        echo 'RUST_INSTALL_SMOKE ' . json_encode($summary, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";

        $expected = [
            $summary['databaseStatus'] === 200,
            $summary['saveStatus'] === 303,
            $summary['saveLocation'] === '/install/?step=admin',
            $summary['adminStatus'] === 200,
            $summary['adminH1'] === '管理员账号',
            $summary['installStatus'] === 303,
            $summary['installLocation'] === '/install/?step=done',
            $summary['doneStatus'] === 200,
            $summary['doneH1'] === '安装完成',
            $summary['hasConfigResult'],
            $summary['hasAdminTokenResult'],
        ];
        if (in_array(false, $expected, true)) {
            fwrite(STDERR, "RUST_INSTALL_SMOKE_FAILED\n");
            return 1;
        }
        echo "RUST_INSTALL_SMOKE_OK install system success path\n";
        return 0;
    }

    private function httpRaw(array &$jar, string $method, string $path, string $body = ''): array
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
                'timeout' => 30,
                'follow_location' => 0,
            ],
        ]);
        $raw = @file_get_contents($this->baseUrl . $path, false, $context);
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
        return $this->firstMatch('/name="csrf_token" value="([a-f0-9]{64})"/su', $body);
    }

    private function firstMatch(string $pattern, string $body): string
    {
        if (preg_match($pattern, $body, $matches) !== 1) {
            return '';
        }
        return trim(html_entity_decode(strip_tags((string)$matches[1]), ENT_QUOTES, 'UTF-8'));
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
}

$check = new InstallSystemStepRustSmoke(
    rtrim(getenv('ACE_RUST_INSTALL_BASE_URL') ?: 'http://127.0.0.1:18082', '/'),
    $dbconfig
);
exit($check->run());
