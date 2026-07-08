<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;

final class AdminCloudStorageParityCheck
{
    private const PREFIX = 'E2E_CLOUD_';
    private const PROVIDER_LOCAL = 'local';
    private const PROVIDER_ALIYUN = 'aliyun_oss';
    private const PROVIDER_TENCENT = 'tencent_cos';
    private const TARGET_BOTH = 'both';
    private const TARGET_PHP = 'php';
    private const TARGET_RUST = 'rust';
    private const CONFIG_COLUMNS = [
        'id',
        'provider',
        'status',
        'is_default',
        'bucket',
        'region',
        'endpoint',
        'access_key',
        'secret_cipher',
        'path_prefix',
        'custom_domain',
        'max_file_size',
        'allowed_extensions',
        'signed_url_ttl_seconds',
        'last_test_status',
        'last_test_message',
        'last_test_at',
        'created_at',
        'updated_at',
    ];
    private const DOWNLOAD_TOKEN_COLUMNS = [
        'id',
        'token_hash',
        'token_cipher',
        'status',
        'last_used_ip',
        'last_used_at',
        'created_at',
        'updated_at',
    ];

    private array $configSnapshot = [];
    private ?array $downloadTokenSnapshot = null;
    private array $objectKeys = [];

    public function __construct(
        private readonly SpringMySQLi $database,
        private readonly string $systemKey,
        private readonly string $phpBaseUrl,
        private readonly string $rustBaseUrl,
        private readonly string $phpProjectRoot,
        private readonly string $rustProjectRoot
    ) {
    }

    public function run(): int
    {
        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        if (in_array('--cleanup-only', $_SERVER['argv'] ?? [], true)) {
            $this->cleanup();
            echo "CLEANED admin cloud storage fixtures\n";
            return 0;
        }

        $this->cleanup();
        $this->snapshotCloudState();
        try {
            $provider = $this->selectedProvider();
            $targetMode = $this->selectedTargetMode();
            if ($targetMode !== self::TARGET_BOTH) {
                $session = $this->createAdminSession();
                $baseUrl = $targetMode === self::TARGET_PHP ? $this->phpBaseUrl : $this->rustBaseUrl;
                $result = $this->runTarget($this->createTarget($targetMode, $baseUrl, $provider), $session);
                $this->printResult($targetMode, $result);
                echo "LIVE_TARGET_OK admin cloud storage target={$targetMode} provider={$provider}\n";
                return 0;
            }
            $phpSession = $this->createAdminSession();
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl, $provider), $phpSession);
            $this->cleanup();
            $this->restoreCloudState();
            $rustSession = $this->createAdminSession();
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl, $provider), $rustSession);
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'adminCloudStorage');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK admin cloud storage\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
                $this->restoreCloudState();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl, string $provider): array
    {
        $suffix = strtoupper(substr($name, 0, 3)) . '_' . strtoupper($this->randomAlpha(6));
        return [
            'name' => $name,
            'provider' => $provider,
            'baseUrl' => rtrim($baseUrl, '/'),
            'filePrefix' => self::PREFIX . 'FILE_' . $suffix . '_',
            'remarkPrefix' => self::PREFIX . 'REMARK_' . $suffix . '_',
            'tokenPrefix' => self::PREFIX . 'TOKEN_' . $suffix . '_',
            'pathPrefix' => self::PREFIX . 'PATH_' . $suffix,
            'root' => $name === 'php' ? $this->phpProjectRoot : $this->rustProjectRoot,
        ];
    }

    private function runTarget(array $target, array $session): array
    {
        $steps = [];
        $configPayload = $this->configPayload($target);
        $steps['configSave'] = $this->normalizeConfigSave($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/config/save',
            $configPayload
        )), $target);
        $steps['configGet'] = $this->normalizeConfigGet($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/config/get',
            []
        )), $target);
        $steps['configTest'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/config/test',
            $configPayload
        ));

        $steps['downloadTokenInitial'] = $this->normalizeDownloadToken($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/download-token/get',
            []
        ))['download_token'] ?? []);
        $refreshData = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/download-token/refresh',
            []
        ));
        $downloadToken = (string)($refreshData['download_token']['token'] ?? '');
        $steps['downloadTokenRefresh'] = $this->normalizeDownloadToken($refreshData['download_token'] ?? []);
        $steps['downloadTokenDisable'] = $this->normalizeDownloadToken($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/download-token/status',
            ['status' => 0]
        ))['download_token'] ?? []);
        $steps['downloadTokenEnable'] = $this->normalizeDownloadToken($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/download-token/status',
            ['status' => 1]
        ))['download_token'] ?? []);

        $adminContent = "admin cloud storage parity\n";
        $adminFile = $this->uploadByAdmin($target, $session, $adminContent);
        $steps['adminTicket'] = $adminFile['ticket'];
        $steps['adminUpload'] = $adminFile['file'];
        $steps['adminObjectBeforeDelete'] = $this->objectFact($target, $adminFile['raw']['object_key']);
        $steps['adminDownload'] = $this->normalizeDownload(
            $target,
            $this->downloadByToken($target, $adminFile['raw']['file_key'], $downloadToken),
            $adminContent,
            $adminFile['raw']['original_name']
        );
        $steps['adminDetail'] = $this->normalizeFile($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/files/detail',
            ['file_id' => $adminFile['raw']['id']]
        ))['file'] ?? [], $target);
        $steps['adminList'] = $this->normalizeFileList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/files/list',
            ['keyword' => $target['filePrefix'], 'status' => 'active', 'limit' => 20]
        ))['files'] ?? [], $target);

        $remoteToken = $this->createRemoteApiToken($target, $session['adminUsername']);
        $remoteContent = "remote cloud storage parity\n";
        $remoteUpload = $this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/upload',
            [
                'original_name' => $target['filePrefix'] . 'remote.txt',
                'content_base64' => chunk_split(base64_encode($remoteContent), 8, "\n"),
                'sha256' => hash('sha256', $remoteContent),
                'mime_type' => 'text/plain',
                'remark' => $target['remarkPrefix'] . 'remote',
            ],
            $remoteToken['accessKey'],
            $remoteToken['secret']
        ));
        $remoteFile = is_array($remoteUpload['file'] ?? null) ? $remoteUpload['file'] : [];
        $steps['remoteUpload'] = $this->normalizeFile($remoteFile, $target);
        $steps['remoteObjectBeforeDelete'] = $this->objectFact($target, (string)($remoteFile['object_key'] ?? ''));
        $steps['remoteDownload'] = $this->normalizeDownload(
            $target,
            $this->downloadByToken($target, (string)($remoteFile['file_key'] ?? ''), $downloadToken),
            $remoteContent,
            (string)($remoteFile['original_name'] ?? '')
        );
        $steps['remoteDetail'] = $this->normalizeFile($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/detail',
            ['file_id' => $remoteFile['id'] ?? 0],
            $remoteToken['accessKey'],
            $remoteToken['secret']
        ))['file'] ?? [], $target);
        $steps['remoteList'] = $this->normalizeFileList($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/list',
            ['keyword' => $target['filePrefix'], 'status' => 'active', 'limit' => 20],
            $remoteToken['accessKey'],
            $remoteToken['secret']
        ))['files'] ?? [], $target);

        $steps['remoteDelete'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/delete',
            ['file_id' => $remoteFile['id'] ?? 0],
            $remoteToken['accessKey'],
            $remoteToken['secret']
        ));
        $steps['remoteObjectAfterDelete'] = $this->objectFact($target, (string)($remoteFile['object_key'] ?? ''));
        $steps['remoteDetailDeleted'] = $this->normalizeFile($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/detail',
            ['file_id' => $remoteFile['id'] ?? 0],
            $remoteToken['accessKey'],
            $remoteToken['secret']
        ))['file'] ?? [], $target);

        $steps['adminDelete'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/files/delete',
            ['file_id' => $adminFile['raw']['id']]
        ));
        $steps['adminObjectAfterDelete'] = $this->objectFact($target, $adminFile['raw']['object_key']);
        $steps['adminDetailDeleted'] = $this->normalizeFile($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/files/detail',
            ['file_id' => $adminFile['raw']['id']]
        ))['file'] ?? [], $target);
        $steps['adminDeleteAgain'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/files/delete',
            ['file_id' => $adminFile['raw']['id']]
        ));
        $steps['listAfterDelete'] = $this->normalizeFileList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/files/list',
            ['keyword' => $target['filePrefix'], 'status' => 'active', 'limit' => 20]
        ))['files'] ?? [], $target);

        return ['steps' => $steps];
    }

    private function uploadByAdmin(array $target, array $session, string $content): array
    {
        $originalName = $target['filePrefix'] . 'admin.txt';
        $ticketData = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cloud-storage/upload-ticket/create',
            [
                'original_name' => $originalName,
                'size_bytes' => strlen($content),
                'sha256' => hash('sha256', $content),
                'mime_type' => 'text/plain',
                'remark' => $target['remarkPrefix'] . 'admin',
            ]
        ));
        $uploadData = $this->successData($this->adminUploadRequest(
            $target,
            $session['token'],
            (string)($ticketData['ticket'] ?? ''),
            $originalName,
            'text/plain',
            $content
        ));
        $file = is_array($uploadData['file'] ?? null) ? $uploadData['file'] : [];
        return [
            'ticket' => $this->normalizeUploadTicket($ticketData),
            'file' => $this->normalizeFile($file, $target),
            'raw' => $file,
        ];
    }

    private function configPayload(array $target): array
    {
        return match ($target['provider']) {
            self::PROVIDER_LOCAL => $this->localConfigPayload($target),
            self::PROVIDER_ALIYUN => $this->aliyunConfigPayload($target),
            self::PROVIDER_TENCENT => $this->tencentConfigPayload($target),
            default => throw new RuntimeException('unsupported cloud provider: ' . $target['provider']),
        };
    }

    private function localConfigPayload(array $target): array
    {
        return [
            'provider' => self::PROVIDER_LOCAL,
            'status' => 1,
            'set_default' => 1,
            'bucket' => '',
            'region' => '',
            'endpoint' => '',
            'access_key' => '',
            'secret' => '',
            'path_prefix' => $target['pathPrefix'],
            'custom_domain' => '',
            'max_file_size' => '4096',
            'allowed_extensions' => 'TXT, bin,txt',
            'signed_url_ttl_seconds' => '300',
        ];
    }

    private function aliyunConfigPayload(array $target): array
    {
        return [
            'provider' => self::PROVIDER_ALIYUN,
            'status' => 1,
            'set_default' => 1,
            'bucket' => $this->requiredEnv('bucket', ['ACE_ALIYUN_OSS_BUCKET', 'ACE_CLOUD_LIVE_BUCKET']),
            'region' => '',
            'endpoint' => $this->requiredEnv('endpoint', ['ACE_ALIYUN_OSS_ENDPOINT', 'ACE_CLOUD_LIVE_ENDPOINT']),
            'access_key' => $this->requiredEnv('access_key', ['ACE_ALIYUN_OSS_ACCESS_KEY', 'ACE_CLOUD_LIVE_ACCESS_KEY']),
            'secret' => $this->requiredEnv('secret', ['ACE_ALIYUN_OSS_SECRET', 'ACE_CLOUD_LIVE_SECRET']),
            'path_prefix' => $target['pathPrefix'],
            'custom_domain' => $this->optionalEnv(['ACE_ALIYUN_OSS_CUSTOM_DOMAIN', 'ACE_CLOUD_LIVE_CUSTOM_DOMAIN']),
            'max_file_size' => '4096',
            'allowed_extensions' => 'TXT, bin,txt',
            'signed_url_ttl_seconds' => '300',
        ];
    }

    private function tencentConfigPayload(array $target): array
    {
        return [
            'provider' => self::PROVIDER_TENCENT,
            'status' => 1,
            'set_default' => 1,
            'bucket' => $this->requiredEnv('bucket', ['ACE_TENCENT_COS_BUCKET', 'ACE_CLOUD_LIVE_BUCKET']),
            'region' => $this->requiredEnv('region', ['ACE_TENCENT_COS_REGION', 'ACE_CLOUD_LIVE_REGION']),
            'endpoint' => '',
            'access_key' => $this->requiredEnv('access_key', ['ACE_TENCENT_COS_ACCESS_KEY', 'ACE_CLOUD_LIVE_ACCESS_KEY']),
            'secret' => $this->requiredEnv('secret', ['ACE_TENCENT_COS_SECRET', 'ACE_CLOUD_LIVE_SECRET']),
            'path_prefix' => $target['pathPrefix'],
            'custom_domain' => $this->optionalEnv(['ACE_TENCENT_COS_CUSTOM_DOMAIN', 'ACE_CLOUD_LIVE_CUSTOM_DOMAIN']),
            'max_file_size' => '4096',
            'allowed_extensions' => 'TXT, bin,txt',
            'signed_url_ttl_seconds' => '300',
        ];
    }

    private function adminRequest(array $target, array $session, string $route, array $payload): array
    {
        $timestamp = (string)time();
        $nonce = Crypto::token(18);
        $plaintext = $payload === [] ? '{}' : $this->json($payload);
        $body = $this->json(Crypto::encryptGcm(
            $plaintext,
            $session['rawKey'],
            "POST\n{$route}\n{$timestamp}\n{$nonce}"
        ));
        $signature = RequestSigner::sign($session['rawKey'], [
            'method' => 'POST',
            'route' => $route,
            'timestamp' => $timestamp,
            'nonce' => $nonce,
            'body' => $body,
        ]);
        $response = $this->httpJson(
            $target['baseUrl'] . '/api/v1/index.php?route=' . rawurlencode($route),
            [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'X-Admin-Session' => $session['token'],
                'X-Timestamp' => $timestamp,
                'X-Nonce' => $nonce,
                'X-Signature' => $signature,
            ],
            $body
        );
        return $this->decryptAdminResponse($response, $session, $route, $nonce);
    }

    private function adminUploadRequest(
        array $target,
        string $sessionToken,
        string $ticket,
        string $fileName,
        string $mimeType,
        string $content
    ): array {
        $boundary = '----AceCloudParity' . bin2hex(random_bytes(8));
        $body = "--{$boundary}\r\n"
            . "Content-Disposition: form-data; name=\"ticket\"\r\n\r\n"
            . $ticket . "\r\n"
            . "--{$boundary}\r\n"
            . 'Content-Disposition: form-data; name="file"; filename="' . $fileName . "\"\r\n"
            . "Content-Type: {$mimeType}\r\n\r\n"
            . $content . "\r\n"
            . "--{$boundary}--\r\n";
        return $this->httpJson(
            $target['baseUrl'] . '/api/v1/index.php?route=' . rawurlencode('/admin/cloud-storage/files/upload'),
            [
                'Accept' => 'application/json',
                'Content-Type' => 'multipart/form-data; boundary=' . $boundary,
                'X-Admin-Session' => $sessionToken,
            ],
            $body
        );
    }

    private function remoteRequest(
        array $target,
        string $route,
        array $payload,
        string $accessKey,
        string $secret
    ): array {
        $timestamp = (string)time();
        $nonce = Crypto::token(18);
        $body = $this->json($payload);
        $signature = RequestSigner::sign($secret, [
            'method' => 'POST',
            'route' => $route,
            'timestamp' => $timestamp,
            'nonce' => $nonce,
            'body' => $body,
        ]);
        return $this->httpJson(
            $target['baseUrl'] . '/api/v1/index.php?route=' . rawurlencode($route),
            [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'X-Remote-Access-Key' => $accessKey,
                'X-Timestamp' => $timestamp,
                'X-Nonce' => $nonce,
                'X-Signature' => $signature,
            ],
            $body
        );
    }

    private function downloadByToken(array $target, string $fileKey, string $downloadToken): array
    {
        return $this->httpRaw(
            $target['baseUrl'] . '/api/v1/index.php?' . http_build_query([
                'route' => '/cloud/download',
                'file_key' => $fileKey,
                'download_token' => $downloadToken,
            ], '', '&', PHP_QUERY_RFC3986)
        );
    }

    private function decryptAdminResponse(array $response, array $session, string $route, string $nonce): array
    {
        $body = $response['body'];
        if (($response['httpStatus'] ?? 0) === 200
            && is_array($body)
            && ($body['code'] ?? null) === 0
            && (($body['data']['encrypted'] ?? false) === true)
        ) {
            $body['data'] = json_decode(Crypto::decryptGcm(
                $body['data']['payload'],
                $session['rawKey'],
                "RESPONSE\n{$route}\n{$nonce}"
            ), true);
        }
        return [
            'route' => $route,
            'httpStatus' => $response['httpStatus'],
            'body' => $body,
        ];
    }

    private function httpJson(string $url, array $headers, string $content): array
    {
        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headerLines),
                'content' => $content,
                'ignore_errors' => true,
                'timeout' => 20,
            ],
        ]);
        $raw = @file_get_contents($url, false, $context);
        $body = json_decode(is_string($raw) ? $raw : '', true);
        return [
            'httpStatus' => $this->httpStatus($http_response_header ?? []),
            'headers' => $http_response_header ?? [],
            'body' => is_array($body) ? $body : ['error' => 'NON_JSON_RESPONSE', 'raw' => $raw],
        ];
    }

    private function httpRaw(string $url): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'ignore_errors' => true,
                'timeout' => 20,
            ],
        ]);
        $raw = @file_get_contents($url, false, $context);
        return [
            'httpStatus' => $this->httpStatus($http_response_header ?? []),
            'headers' => $http_response_header ?? [],
            'body' => is_string($raw) ? $raw : '',
        ];
    }

    private function successData(array $step): array
    {
        $body = $step['body'] ?? null;
        if (($step['httpStatus'] ?? 0) !== 200 || !is_array($body) || ($body['code'] ?? null) !== 0) {
            throw new RuntimeException('request failed: ' . $this->json($step));
        }
        $data = $body['data'] ?? [];
        if (!is_array($data)) {
            throw new RuntimeException('response data is not object: ' . $this->json($step));
        }
        return $data;
    }

    private function normalizeConfigSave(array $data, array $target): array
    {
        return [
            'saved' => (bool)($data['saved'] ?? false),
            'config' => $this->normalizeConfig($data['config'] ?? [], $target),
        ];
    }

    private function normalizeConfigGet(array $data, array $target): array
    {
        $selectedConfig = [];
        foreach (is_array($data['configs'] ?? null) ? $data['configs'] : [] as $config) {
            if (($config['provider']['value'] ?? '') === $target['provider']) {
                $selectedConfig = $this->normalizeConfig($config, $target);
            }
        }
        return [
            'providers' => array_map(
                static fn(array $provider): string => (string)($provider['value'] ?? ''),
                is_array($data['providers'] ?? null) ? $data['providers'] : []
            ),
            'selected_config' => $selectedConfig,
            'default_provider' => (string)($data['default_config']['provider']['value'] ?? ''),
        ];
    }

    private function normalizeConfig(mixed $config, array $target): array
    {
        $config = is_array($config) ? $config : [];
        return [
            'keys' => $this->sortedKeys($config),
            'id' => $this->dynamicId($config['id'] ?? null),
            'provider' => (string)($config['provider']['value'] ?? ''),
            'status' => $this->typedValue($config['status'] ?? null),
            'is_default' => $this->typedValue($config['is_default'] ?? null),
            'secret_saved' => $this->typedValue($config['secret_saved'] ?? null),
            'path_prefix' => $this->normalizePathPrefix((string)($config['path_prefix'] ?? ''), $target),
            'max_file_size' => $this->typedValue($config['max_file_size'] ?? null),
            'allowed_extensions' => (string)($config['allowed_extensions'] ?? ''),
            'signed_url_ttl_seconds' => $this->typedValue($config['signed_url_ttl_seconds'] ?? null),
            'last_test_status_state' => trim((string)($config['last_test_status'] ?? '')) === '' ? 'empty' : 'present',
            'last_test_message_state' => trim((string)($config['last_test_message'] ?? '')) === '' ? 'empty' : 'present',
            'last_test_at_state' => trim((string)($config['last_test_at'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function normalizeUploadTicket(array $data): array
    {
        return [
            'ticket' => $this->tokenState($data['ticket'] ?? null),
            'expires_at_state' => ((int)($data['expires_at'] ?? 0)) > time() ? 'future' : 'invalid',
            'provider' => (string)($data['provider']['value'] ?? ''),
            'upload_url' => (string)($data['upload_url'] ?? ''),
        ];
    }

    private function normalizeDownloadToken(mixed $token): array
    {
        $token = is_array($token) ? $token : [];
        return [
            'status' => $this->typedValue($token['status'] ?? null),
            'token' => $this->tokenState($token['token'] ?? null),
            'last_used_ip_state' => $this->localIpState((string)($token['last_used_ip'] ?? '')),
            'last_used_at_state' => trim((string)($token['last_used_at'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function normalizeFileList(mixed $files, array $target): array
    {
        $rows = [];
        foreach (is_array($files) ? $files : [] as $file) {
            $rows[] = $this->normalizeFile($file, $target);
        }
        usort($rows, static fn(array $left, array $right): int => strcmp($left['original_name'], $right['original_name']));
        return $rows;
    }

    private function normalizeFile(mixed $file, array $target): array
    {
        $file = is_array($file) ? $file : [];
        return [
            'keys' => $this->sortedKeys($file),
            'id' => $this->dynamicId($file['id'] ?? null),
            'file_key' => $this->fileKeyState($file['file_key'] ?? null),
            'provider' => (string)($file['provider']['value'] ?? ''),
            'original_name' => $this->normalizeTargetText((string)($file['original_name'] ?? ''), $target),
            'mime_type' => (string)($file['mime_type'] ?? ''),
            'extension' => (string)($file['extension'] ?? ''),
            'size_bytes' => $this->typedValue($file['size_bytes'] ?? null),
            'sha256_state' => $this->sha256State($file['sha256'] ?? null),
            'object_key' => $this->objectKeyState((string)($file['object_key'] ?? ''), $target),
            'status' => (string)($file['status'] ?? ''),
            'remark' => $this->normalizeTargetText((string)($file['remark'] ?? ''), $target),
            'download_count' => $this->downloadCountState($file['download_count'] ?? null),
            'last_download_ip_state' => $this->localIpState((string)($file['last_download_ip'] ?? '')),
            'last_download_at_state' => trim((string)($file['last_download_at'] ?? '')) === '' ? 'empty' : 'present',
            'created_at_state' => trim((string)($file['created_at'] ?? '')) === '' ? 'empty' : 'present',
            'updated_at_state' => trim((string)($file['updated_at'] ?? '')) === '' ? 'empty' : 'present',
            'external_download_path' => $this->downloadPathState((string)($file['external_download_path'] ?? ''), (string)($file['file_key'] ?? '')),
        ];
    }

    private function normalizeDownload(array $target, array $response, string $expectedContent, string $expectedFileName): array
    {
        $contentType = $this->headerValue($response['headers'], 'Content-Type');
        $contentDisposition = $this->headerValue($response['headers'], 'Content-Disposition');
        $contentLengthMatches = $target['provider'] === self::PROVIDER_LOCAL
            ? (int)$this->headerValue($response['headers'], 'Content-Length') === strlen($expectedContent)
            : 'redirected_external';
        return [
            'httpStatus' => (int)$response['httpStatus'],
            'body_matches' => $response['body'] === $expectedContent,
            'content_type' => strtolower(strtok($contentType, ';') ?: $contentType),
            'content_length_matches' => $contentLengthMatches,
            'disposition_has_name' => str_contains(rawurldecode($contentDisposition), $expectedFileName),
        ];
    }

    private function objectFact(array $target, string $objectKey): array
    {
        if ($target['provider'] !== self::PROVIDER_LOCAL) {
            return [
                'object_key' => $this->objectKeyState($objectKey, $target),
                'provider' => $target['provider'],
                'state' => 'external_provider',
            ];
        }
        return $this->localObjectFact($target, $objectKey);
    }

    private function localObjectFact(array $target, string $objectKey): array
    {
        $path = $this->localObjectPath($target['root'], $objectKey);
        clearstatcache(true, $path);
        return [
            'object_key' => $this->objectKeyState($objectKey, $target),
            'exists' => is_file($path),
        ];
    }

    private function selectedProvider(): string
    {
        $provider = strtolower($this->optionalEnv(['ACE_CLOUD_LIVE_PROVIDER']));
        if ($provider === '') {
            return self::PROVIDER_LOCAL;
        }
        if (!in_array($provider, [self::PROVIDER_LOCAL, self::PROVIDER_ALIYUN, self::PROVIDER_TENCENT], true)) {
            throw new RuntimeException('unsupported ACE_CLOUD_LIVE_PROVIDER: ' . $provider);
        }
        return $provider;
    }

    private function selectedTargetMode(): string
    {
        $target = strtolower($this->optionalEnv(['ACE_CLOUD_LIVE_TARGET']));
        if ($target === '') {
            return self::TARGET_BOTH;
        }
        if (!in_array($target, [self::TARGET_BOTH, self::TARGET_PHP, self::TARGET_RUST], true)) {
            throw new RuntimeException('unsupported ACE_CLOUD_LIVE_TARGET: ' . $target);
        }
        return $target;
    }

    private function requiredEnv(string $logicalName, array $names): string
    {
        $value = $this->optionalEnv($names);
        if ($value === '') {
            throw new RuntimeException('missing cloud provider environment: ' . $logicalName . '=' . implode('|', $names));
        }
        return $value;
    }

    private function optionalEnv(array $names): string
    {
        foreach ($names as $name) {
            $value = getenv($name);
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        return '';
    }

    private function createAdminSession(): array
    {
        $username = self::PREFIX . 'admin_' . strtolower($this->randomAlpha(8));
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity Cloud Storage Admin', $this->rustBaseUrl]
        );
        $token = Crypto::token();
        $keyText = Crypto::encodeBase64Url(random_bytes(32));
        $this->exec(
            'INSERT INTO `auth_admin_sessions` (`token_hash`, `key_cipher`, `ip`, `admin_username`, `expires_at`, `status`) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), ?)',
            [Crypto::sha256($token), Crypto::encryptSecret($keyText, $this->systemKey), '127.0.0.1', $username, 1]
        );
        return [
            'token' => $token,
            'rawKey' => Crypto::decodeBase64Url($keyText),
            'adminUsername' => $username,
        ];
    }

    private function createRemoteApiToken(array $target, string $createdBy): array
    {
        $accessKey = Crypto::token(24);
        $secret = Crypto::token(32);
        $this->exec(
            'INSERT INTO `auth_remote_api_tokens` (`name`, `access_key`, `secret_cipher`, `status`, `expires_at`, `ip_allowlist_json`, `created_by`) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 2 HOUR), ?, ?)',
            [
                $target['tokenPrefix'] . 'primary',
                $accessKey,
                Crypto::encryptSecret($secret, $this->systemKey),
                1,
                $this->json(['127.0.0.1']),
                $createdBy,
            ]
        );
        return ['accessKey' => $accessKey, 'secret' => $secret];
    }

    private function snapshotCloudState(): void
    {
        $columns = implode('`, `', self::CONFIG_COLUMNS);
        $this->configSnapshot = $this->database->selectV2("SELECT `{$columns}` FROM `auth_cloud_storage_configs` ORDER BY `id` ASC");
        $tokenColumns = implode('`, `', self::DOWNLOAD_TOKEN_COLUMNS);
        $row = $this->database->selectRowV2("SELECT `{$tokenColumns}` FROM `auth_cloud_download_token` WHERE `id` = 1");
        $this->downloadTokenSnapshot = is_array($row) ? $row : null;
    }

    private function restoreCloudState(): void
    {
        $snapshotByProvider = [];
        foreach ($this->configSnapshot as $row) {
            $snapshotByProvider[(string)$row['provider']] = $row;
        }
        $currentRows = $this->database->selectV2('SELECT `id`, `provider` FROM `auth_cloud_storage_configs`');
        foreach ($currentRows as $row) {
            $provider = (string)$row['provider'];
            if (!array_key_exists($provider, $snapshotByProvider)) {
                $this->exec('DELETE FROM `auth_cloud_storage_configs` WHERE `id` = ?', [(int)$row['id']]);
            }
        }
        foreach ($this->configSnapshot as $row) {
            $this->restoreConfigRow($row);
        }
        $this->restoreDownloadToken();
    }

    private function restoreConfigRow(array $row): void
    {
        $this->exec(
            'INSERT INTO `auth_cloud_storage_configs` (`id`, `provider`, `status`, `is_default`, `bucket`, `region`, `endpoint`, `access_key`, `secret_cipher`, `path_prefix`, `custom_domain`, `max_file_size`, `allowed_extensions`, `signed_url_ttl_seconds`, `last_test_status`, `last_test_message`, `last_test_at`, `created_at`, `updated_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE `id` = VALUES(`id`), `provider` = VALUES(`provider`), `status` = VALUES(`status`), `is_default` = VALUES(`is_default`), `bucket` = VALUES(`bucket`), `region` = VALUES(`region`), `endpoint` = VALUES(`endpoint`), `access_key` = VALUES(`access_key`), `secret_cipher` = VALUES(`secret_cipher`), `path_prefix` = VALUES(`path_prefix`), `custom_domain` = VALUES(`custom_domain`), `max_file_size` = VALUES(`max_file_size`), `allowed_extensions` = VALUES(`allowed_extensions`), `signed_url_ttl_seconds` = VALUES(`signed_url_ttl_seconds`), `last_test_status` = VALUES(`last_test_status`), `last_test_message` = VALUES(`last_test_message`), `last_test_at` = VALUES(`last_test_at`), `created_at` = VALUES(`created_at`), `updated_at` = VALUES(`updated_at`)',
            [
                (int)$row['id'],
                (string)$row['provider'],
                (int)$row['status'],
                (int)$row['is_default'],
                (string)$row['bucket'],
                (string)$row['region'],
                (string)$row['endpoint'],
                (string)$row['access_key'],
                $row['secret_cipher'] ?? null,
                (string)$row['path_prefix'],
                (string)$row['custom_domain'],
                (int)$row['max_file_size'],
                (string)$row['allowed_extensions'],
                (int)$row['signed_url_ttl_seconds'],
                (string)$row['last_test_status'],
                (string)$row['last_test_message'],
                $row['last_test_at'] ?? null,
                (string)$row['created_at'],
                (string)$row['updated_at'],
            ]
        );
    }

    private function restoreDownloadToken(): void
    {
        if ($this->downloadTokenSnapshot === null) {
            $this->exec('DELETE FROM `auth_cloud_download_token` WHERE `id` = 1', []);
            return;
        }
        $row = $this->downloadTokenSnapshot;
        $this->exec(
            'INSERT INTO `auth_cloud_download_token` (`id`, `token_hash`, `token_cipher`, `status`, `last_used_ip`, `last_used_at`, `created_at`, `updated_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE `token_hash` = VALUES(`token_hash`), `token_cipher` = VALUES(`token_cipher`), `status` = VALUES(`status`), `last_used_ip` = VALUES(`last_used_ip`), `last_used_at` = VALUES(`last_used_at`), `created_at` = VALUES(`created_at`), `updated_at` = VALUES(`updated_at`)',
            [
                (int)$row['id'],
                (string)$row['token_hash'],
                $row['token_cipher'] ?? null,
                (int)$row['status'],
                (string)$row['last_used_ip'],
                $row['last_used_at'] ?? null,
                (string)$row['created_at'],
                (string)$row['updated_at'],
            ]
        );
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
        $this->deleteRemoteApiRows();
        $this->deleteCloudRows();
        $this->exec('DELETE FROM `sub_admin` WHERE `username` LIKE ?', [self::PREFIX . '%']);
        $this->deleteLocalObjects();
    }

    private function deleteAdminSessions(): void
    {
        if ($this->tableExists('auth_admin_nonces')) {
            $sessions = $this->database->selectV2('SELECT `id` FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', [self::PREFIX . '%']);
            foreach ($sessions as $session) {
                $this->exec('DELETE FROM `auth_admin_nonces` WHERE `session_id` = ?', [(int)$session['id']]);
            }
        }
        $this->exec('DELETE FROM `auth_admin_sessions` WHERE `admin_username` LIKE ?', [self::PREFIX . '%']);
    }

    private function deleteRemoteApiRows(): void
    {
        $tokens = $this->database->selectV2('SELECT `id`, `access_key` FROM `auth_remote_api_tokens` WHERE `name` LIKE ?', [self::PREFIX . 'TOKEN_%']);
        $tokenIds = $this->columnInts($tokens, 'id');
        $accessKeys = $this->columnStrings($tokens, 'access_key');
        if ($tokenIds !== []) {
            $this->execIn('DELETE FROM `auth_remote_api_nonces` WHERE `token_id` IN (%s)', $tokenIds);
            $this->execIn('DELETE FROM `auth_remote_api_logs` WHERE `token_id` IN (%s)', $tokenIds);
        }
        if ($accessKeys !== []) {
            $this->execIn('DELETE FROM `auth_remote_api_logs` WHERE `access_key` IN (%s)', $accessKeys);
        }
        $this->exec('DELETE FROM `auth_remote_api_tokens` WHERE `name` LIKE ?', [self::PREFIX . 'TOKEN_%']);
    }

    private function deleteCloudRows(): void
    {
        $files = $this->database->selectV2(
            'SELECT `object_key` FROM `auth_cloud_files` WHERE `original_name` LIKE ? OR `remark` LIKE ? OR `object_key` LIKE ?',
            [self::PREFIX . '%', self::PREFIX . '%', self::PREFIX . 'PATH_%']
        );
        foreach ($files as $file) {
            $this->objectKeys[] = (string)$file['object_key'];
        }
        $this->exec(
            'DELETE FROM `auth_cloud_files` WHERE `original_name` LIKE ? OR `remark` LIKE ? OR `object_key` LIKE ?',
            [self::PREFIX . '%', self::PREFIX . '%', self::PREFIX . 'PATH_%']
        );
        $this->exec(
            'DELETE FROM `auth_cloud_upload_tickets` WHERE `original_name` LIKE ? OR `remark` LIKE ?',
            [self::PREFIX . '%', self::PREFIX . '%']
        );
    }

    private function deleteLocalObjects(): void
    {
        foreach (array_unique($this->objectKeys) as $objectKey) {
            foreach ([$this->phpProjectRoot, $this->rustProjectRoot] as $root) {
                $path = $this->localObjectPath($root, $objectKey);
                if (is_file($path)) {
                    @unlink($path);
                    $this->pruneEmptyParents(dirname($path), $this->cloudStorageRoot($root));
                }
            }
        }
        $this->objectKeys = [];
    }

    private function localObjectPath(string $projectRoot, string $objectKey): string
    {
        $normalizedKey = str_replace('\\', '/', trim($objectKey, '/'));
        if ($normalizedKey === '' || str_contains($normalizedKey, '..') || str_contains($normalizedKey, "\0")) {
            return $this->cloudStorageRoot($projectRoot) . DIRECTORY_SEPARATOR . '__invalid__';
        }
        return $this->cloudStorageRoot($projectRoot)
            . DIRECTORY_SEPARATOR
            . str_replace('/', DIRECTORY_SEPARATOR, $normalizedKey);
    }

    private function cloudStorageRoot(string $projectRoot): string
    {
        return rtrim($projectRoot, DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR
            . 'storage'
            . DIRECTORY_SEPARATOR
            . 'cloud-storage';
    }

    private function pruneEmptyParents(string $directory, string $stopDirectory): void
    {
        $stop = rtrim($stopDirectory, DIRECTORY_SEPARATOR);
        $current = rtrim($directory, DIRECTORY_SEPARATOR);
        while ($current !== '' && $current !== $stop && str_starts_with($current, $stop)) {
            if (@rmdir($current) !== true) {
                return;
            }
            $current = dirname($current);
        }
    }

    private function dynamicId(mixed $value): array
    {
        $id = (int)$value;
        return [
            'type' => get_debug_type($value),
            'state' => $id > 0 ? 'present' : 'missing',
        ];
    }

    private function typedValue(mixed $value): array
    {
        return ['type' => get_debug_type($value), 'value' => $value];
    }

    private function tokenState(mixed $value): array
    {
        $token = (string)$value;
        return [
            'type' => get_debug_type($value),
            'length' => strlen($token),
            'token_text' => preg_match('/^[A-Za-z0-9_-]*$/', $token) === 1,
        ];
    }

    private function fileKeyState(mixed $value): array
    {
        $fileKey = (string)$value;
        return [
            'type' => get_debug_type($value),
            'prefix' => str_starts_with($fileKey, 'cf_') ? 'cf' : 'other',
            'length' => strlen($fileKey),
        ];
    }

    private function sha256State(mixed $value): array
    {
        $hash = (string)$value;
        return [
            'type' => get_debug_type($value),
            'valid' => preg_match('/^[a-f0-9]{64}$/', $hash) === 1,
        ];
    }

    private function objectKeyState(string $objectKey, array $target): array
    {
        return [
            'prefix' => str_starts_with($objectKey, $target['pathPrefix'] . '/') ? '<target_path>' : 'other',
            'extension' => pathinfo($objectKey, PATHINFO_EXTENSION),
            'has_date_path' => preg_match('~/' . date('Y') . '/' . date('m') . '/~', $objectKey) === 1,
        ];
    }

    private function downloadPathState(string $path, string $fileKey): array
    {
        return [
            'route' => str_contains($path, 'route=%2Fcloud%2Fdownload'),
            'has_file_key' => $fileKey !== '' && str_contains($path, $fileKey),
        ];
    }

    private function downloadCountState(mixed $value): array
    {
        return [
            'type' => get_debug_type($value),
            'at_least_one' => (int)$value >= 1,
        ];
    }

    private function localIpState(string $ip): string
    {
        if ($ip === '') {
            return 'empty';
        }
        return in_array($ip, ['127.0.0.1', '::1'], true) ? 'local' : 'other';
    }

    private function normalizePathPrefix(string $pathPrefix, array $target): string
    {
        return $pathPrefix === $target['pathPrefix'] ? '<target_path>' : $pathPrefix;
    }

    private function normalizeTargetText(string $value, array $target): string
    {
        return str_replace(
            [$target['filePrefix'], $target['remarkPrefix'], $target['tokenPrefix'], $target['pathPrefix']],
            ['<file>.', '<remark>.', '<token>.', '<target_path>'],
            $value
        );
    }

    private function sortedKeys(array $row): array
    {
        $keys = array_map('strval', array_keys($row));
        sort($keys);
        return $keys;
    }

    private function columnInts(array $rows, string $key): array
    {
        return array_values(array_filter(array_map(
            static fn(array $row): int => (int)($row[$key] ?? 0),
            $rows
        ), static fn(int $value): bool => $value > 0));
    }

    private function columnStrings(array $rows, string $key): array
    {
        return array_values(array_filter(array_map(
            static fn(array $row): string => (string)($row[$key] ?? ''),
            $rows
        ), static fn(string $value): bool => $value !== ''));
    }

    private function execIn(string $sql, array $values): void
    {
        if ($values === []) {
            return;
        }
        $placeholders = implode(', ', array_fill(0, count($values), '?'));
        $this->exec(sprintf($sql, $placeholders), array_values($values));
    }

    private function exec(string $sql, array $params): int|string
    {
        $result = $this->database->exec($sql, $params);
        if ($result === false) {
            throw new RuntimeException($this->database->getError() ?: 'database statement failed');
        }
        return $result;
    }

    private function tableExists(string $table): bool
    {
        return is_array($this->database->selectRowV2('SHOW TABLES LIKE ?', [$table]));
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

    private function httpStatus(array $headers): int
    {
        foreach ($headers as $header) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', (string)$header, $matches) === 1) {
                return (int)$matches[1];
            }
        }
        return 0;
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

$check = new AdminCloudStorageParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080',
    $phpProjectRoot,
    getenv('ACE_RUST_ROOT') ?: 'D:\\Desktop\\0\\网络验证rust'
);
exit($check->run());
