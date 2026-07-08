<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;

final class RemoteApiCloudStorageParityCheck
{
    private const PREFIX = 'E2E_RCLOUD_';
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
        if (in_array('--cleanup-only', $_SERVER['argv'] ?? [], true)) {
            $this->cleanup();
            echo "CLEANED remote api cloud storage fixtures\n";
            return 0;
        }

        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        $this->snapshotCloudState();
        try {
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl));
            $this->cleanup();
            $this->restoreCloudState();
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl));
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'remoteApiCloudStorage');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK remote api cloud storage\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
                $this->restoreCloudState();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $suffix = strtoupper(substr($name, 0, 3)) . '_' . strtoupper($this->randomAlpha(6));
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'pathPrefix' => self::PREFIX . 'PATH_' . $suffix,
            'filePrefix' => self::PREFIX . 'FILE_' . $suffix . '_',
            'remarkPrefix' => self::PREFIX . 'REMARK_' . $suffix . '_',
            'tokenName' => self::PREFIX . 'TOKEN_' . $suffix,
            'root' => $name === 'php' ? $this->phpProjectRoot : $this->rustProjectRoot,
        ];
    }

    private function runTarget(array $target): array
    {
        $secret = Crypto::token(32);
        $accessKey = Crypto::token(24);
        $tokenId = $this->insertRemoteApiToken($target['tokenName'], $accessKey, $secret);
        $configPayload = $this->localConfigPayload($target);
        $steps = [];

        $steps['configSave'] = $this->normalizeConfigSave($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/config/save',
            $configPayload,
            $accessKey,
            $secret
        )), $target);
        $steps['configGet'] = $this->normalizeConfigGet($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/config/get',
            [],
            $accessKey,
            $secret
        )), $target);
        $steps['configTest'] = $this->normalizeConfigTest($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/config/test',
            $configPayload,
            $accessKey,
            $secret
        )));
        $steps['summaryAfterConfig'] = $this->normalizeSummary($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/summary',
            [],
            $accessKey,
            $secret
        )), $target);
        $fileContent = "remote api cloud storage parity\n";
        $fileUpload = $this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/upload',
            [
                'original_name' => $target['filePrefix'] . 'remote.txt',
                'content_base64' => chunk_split(base64_encode($fileContent), 8, "\n"),
                'sha256' => hash('sha256', $fileContent),
                'mime_type' => 'text/plain',
                'remark' => $target['remarkPrefix'] . 'remote',
            ],
            $accessKey,
            $secret
        ));
        $uploadedFile = is_array($fileUpload['file'] ?? null) ? $fileUpload['file'] : [];
        $steps['fileUpload'] = $this->normalizeFile($uploadedFile, $target);
        $steps['fileObjectBeforeDelete'] = $this->objectFact($target, (string)($uploadedFile['object_key'] ?? ''));
        $steps['fileDetail'] = $this->normalizeFile($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/detail',
            ['file_id' => $uploadedFile['id'] ?? 0],
            $accessKey,
            $secret
        ))['file'] ?? [], $target);
        $steps['fileList'] = $this->normalizeFileList($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/list',
            ['keyword' => $target['filePrefix'], 'status' => 'active', 'limit' => 20],
            $accessKey,
            $secret
        ))['files'] ?? [], $target);
        $steps['fileDelete'] = $this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/delete',
            ['file_id' => $uploadedFile['id'] ?? 0],
            $accessKey,
            $secret
        ));
        $steps['fileObjectAfterDelete'] = $this->objectFact($target, (string)($uploadedFile['object_key'] ?? ''));
        $steps['fileDetailDeleted'] = $this->normalizeFile($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/files/detail',
            ['file_id' => $uploadedFile['id'] ?? 0],
            $accessKey,
            $secret
        ))['file'] ?? [], $target);
        $steps['downloadTokenInitial'] = $this->normalizeDownloadToken($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/download-token/get',
            [],
            $accessKey,
            $secret
        ))['download_token'] ?? []);
        $steps['downloadTokenRefresh'] = $this->normalizeDownloadToken($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/download-token/refresh',
            [],
            $accessKey,
            $secret
        ))['download_token'] ?? []);
        $steps['downloadTokenDisable'] = $this->normalizeDownloadToken($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/download-token/status',
            ['status' => 0],
            $accessKey,
            $secret
        ))['download_token'] ?? []);
        $steps['downloadTokenEnable'] = $this->normalizeDownloadToken($this->successData($this->remoteRequest(
            $target,
            '/remote/cloud-storage/download-token/status',
            ['status' => 1],
            $accessKey,
            $secret
        ))['download_token'] ?? []);
        $steps['invalidProviderError'] = $this->normalizeError($this->remoteRequest(
            $target,
            '/remote/cloud-storage/config/test',
            ['provider' => 'bad_provider'],
            $accessKey,
            $secret
        ));
        $steps['logs'] = $this->remoteLogFacts($accessKey);
        $steps['audits'] = $this->auditFacts($target);
        $steps['tokenTouched'] = $this->tokenTouchedFact($tokenId);

        return ['steps' => $steps];
    }

    private function localConfigPayload(array $target): array
    {
        return [
            'provider' => 'local',
            'status' => 1,
            'set_default' => 1,
            'bucket' => '',
            'region' => '',
            'endpoint' => '',
            'access_key' => '',
            'secret' => '',
            'path_prefix' => $target['pathPrefix'],
            'custom_domain' => '',
            'max_file_size' => '8192',
            'allowed_extensions' => 'TXT, bin,txt',
            'signed_url_ttl_seconds' => '300',
        ];
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
        $body = $payload === [] ? '{}' : $this->json($payload);
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
            'body' => is_array($body) ? $body : ['raw' => is_string($raw) ? $raw : ''],
        ];
    }

    private function successData(array $response): array
    {
        $body = is_array($response['body'] ?? null) ? $response['body'] : [];
        if ((int)($response['httpStatus'] ?? 0) !== 200 || (int)($body['code'] ?? -1) !== 0 || !is_array($body['data'] ?? null)) {
            throw new RuntimeException('unexpected success response: ' . $this->json($response));
        }
        return $body['data'];
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
            if (($config['provider']['value'] ?? '') === 'local') {
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

    private function normalizeSummary(array $data, array $target): array
    {
        $providerCounts = is_array($data['provider_counts'] ?? null) ? $data['provider_counts'] : [];
        $counts = [];
        foreach (['local', 'aliyun_oss', 'tencent_cos'] as $provider) {
            $counts[$provider] = [
                'file_count_state' => array_key_exists($provider, $providerCounts) ? 'present' : 'missing',
                'size_total_state' => array_key_exists($provider, $providerCounts) ? 'present' : 'missing',
            ];
        }
        return [
            'file_total_state' => array_key_exists('file_total', $data) ? 'present' : 'missing',
            'size_total_state' => array_key_exists('size_total', $data) ? 'present' : 'missing',
            'provider_counts' => $counts,
            'default_config' => $this->normalizeConfig($data['default_config'] ?? [], $target),
            'download_token' => $this->normalizeDownloadToken($data['download_token'] ?? []),
        ];
    }

    private function normalizeConfig(mixed $config, array $target): array
    {
        $config = is_array($config) ? $config : [];
        return [
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

    private function normalizeConfigTest(array $data): array
    {
        return [
            'status' => (string)($data['status'] ?? ''),
            'message_state' => trim((string)($data['message'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function normalizeDownloadToken(mixed $token): array
    {
        $token = is_array($token) ? $token : [];
        return [
            'status' => $this->typedValue($token['status'] ?? null),
            'token' => trim((string)($token['token'] ?? '')) === '' ? 'empty' : 'present',
            'last_used_ip_state' => $this->normalizeIp((string)($token['last_used_ip'] ?? '')),
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
            'last_download_ip_state' => $this->normalizeIp((string)($file['last_download_ip'] ?? '')),
            'last_download_at_state' => trim((string)($file['last_download_at'] ?? '')) === '' ? 'empty' : 'present',
            'created_at_state' => trim((string)($file['created_at'] ?? '')) === '' ? 'empty' : 'present',
            'updated_at_state' => trim((string)($file['updated_at'] ?? '')) === '' ? 'empty' : 'present',
            'external_download_path' => $this->downloadPathState((string)($file['external_download_path'] ?? ''), (string)($file['file_key'] ?? '')),
        ];
    }

    private function objectFact(array $target, string $objectKey): array
    {
        $path = $this->localObjectPath($target['root'], $objectKey);
        clearstatcache(true, $path);
        return [
            'object_key' => $this->objectKeyState($objectKey, $target),
            'exists' => is_file($path),
        ];
    }

    private function normalizeError(array $response): array
    {
        $body = is_array($response['body'] ?? null) ? $response['body'] : [];
        return [
            'httpStatus' => (int)($response['httpStatus'] ?? 0),
            'code' => (int)($body['code'] ?? -1),
            'error' => (string)($body['error'] ?? ''),
        ];
    }

    private function remoteLogFacts(string $accessKey): array
    {
        $rows = $this->database->selectV2(
            'SELECT `route`, `target_app_id`, `status`, `error_code`, `message`, `ip` FROM `auth_remote_api_logs` WHERE `access_key` = ? ORDER BY `id` ASC',
            [$accessKey]
        );
        $facts = [];
        foreach ($rows as $row) {
            $facts[] = [
                'route' => (string)($row['route'] ?? ''),
                'target_app_id' => (int)($row['target_app_id'] ?? 0) > 0 ? '<app>' : 'null',
                'status' => (string)($row['status'] ?? ''),
                'error_code' => (string)($row['error_code'] ?? ''),
                'message_state' => trim((string)($row['message'] ?? '')) === '' ? 'empty' : 'present',
                'ip' => $this->normalizeIp((string)($row['ip'] ?? '')),
            ];
        }
        return $facts;
    }

    private function auditFacts(array $target): array
    {
        $rows = $this->database->selectV2(
            'SELECT `app_id`, `action`, `message`, `ip` FROM `auth_audit_logs` WHERE `action` IN (?, ?, ?, ?, ?) AND `message` LIKE ? ORDER BY `id` ASC',
            [
                'remote_cloud_file_upload',
                'remote_cloud_file_delete',
                'remote_cloud_config_save',
                'remote_cloud_token_refresh',
                'remote_cloud_token_status',
                '%Token：' . $target['tokenName'] . '%',
            ]
        );
        $facts = [];
        foreach ($rows as $row) {
            $facts[] = [
                'app_id' => (int)($row['app_id'] ?? 0) > 0 ? '<app>' : 'null',
                'action' => (string)($row['action'] ?? ''),
                'message_state' => str_contains((string)($row['message'] ?? ''), $target['tokenName']) ? 'token_name' : 'other',
                'ip' => $this->normalizeIp((string)($row['ip'] ?? '')),
            ];
        }
        return $facts;
    }

    private function tokenTouchedFact(int $tokenId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `last_used_at`, `last_ip` FROM `auth_remote_api_tokens` WHERE `id` = ?',
            [$tokenId]
        );
        return [
            'last_used_at_state' => trim((string)($row['last_used_at'] ?? '')) === '' ? 'empty' : 'present',
            'last_ip' => $this->normalizeIp((string)($row['last_ip'] ?? '')),
        ];
    }

    private function insertRemoteApiToken(string $name, string $accessKey, string $secret): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_remote_api_tokens` (`name`, `access_key`, `secret_cipher`, `status`, `expires_at`, `ip_allowlist_json`, `created_by`) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [
                $name,
                $accessKey,
                Crypto::encryptSecret($secret, $this->systemKey),
                1,
                date('Y-m-d H:i:s', time() + 7200),
                $this->json(['127.0.0.1']),
                self::PREFIX . 'seed',
            ]
        );
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
        $this->deleteRemoteApiRows();
        $this->deleteCloudRows();
        $this->exec('DELETE FROM `auth_audit_logs` WHERE `message` LIKE ?', ['%Token：' . self::PREFIX . 'TOKEN_%']);
        $this->deleteLocalObjects();
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
            [self::PREFIX . 'FILE_%', self::PREFIX . 'REMARK_%', self::PREFIX . 'PATH_%']
        );
        foreach ($files as $file) {
            $this->objectKeys[] = (string)($file['object_key'] ?? '');
        }
        $this->exec(
            'DELETE FROM `auth_cloud_files` WHERE `original_name` LIKE ? OR `remark` LIKE ? OR `object_key` LIKE ?',
            [self::PREFIX . 'FILE_%', self::PREFIX . 'REMARK_%', self::PREFIX . 'PATH_%']
        );
        if ($this->tableExists('auth_cloud_upload_tickets')) {
            $this->exec(
                'DELETE FROM `auth_cloud_upload_tickets` WHERE `original_name` LIKE ? OR `remark` LIKE ?',
                [self::PREFIX . 'FILE_%', self::PREFIX . 'REMARK_%']
            );
        }
    }

    private function deleteLocalObjects(): void
    {
        foreach (array_unique(array_filter($this->objectKeys)) as $objectKey) {
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

    private function dynamicId(mixed $value): string
    {
        return ((int)$value) > 0 ? '<id>' : '0';
    }

    private function normalizePathPrefix(string $value, array $target): string
    {
        return str_replace($target['pathPrefix'], '<pathPrefix>', $value);
    }

    private function normalizeIp(string $ip): string
    {
        return $ip === '127.0.0.1' || $ip === '::1' ? '<local>' : ($ip === '' ? 'empty' : 'other');
    }

    private function typedValue(mixed $value): string
    {
        return gettype($value) . ':' . (is_scalar($value) ? (string)$value : $this->jsonScalar($value));
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
        if ($objectKey !== '') {
            $this->objectKeys[] = $objectKey;
        }
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
            'at_least_zero' => (int)$value >= 0,
        ];
    }

    private function normalizeTargetText(string $value, array $target): string
    {
        return str_replace(
            [$target['filePrefix'], $target['remarkPrefix'], $target['tokenName'], $target['pathPrefix']],
            ['<file>.', '<remark>.', '<token>', '<pathPrefix>'],
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
        return $left === $right ? [] : [$path . ' php=' . $this->jsonScalar($left) . ' rust=' . $this->jsonScalar($right)];
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

$check = new RemoteApiCloudStorageParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080',
    $phpProjectRoot,
    getenv('ACE_RUST_ROOT') ?: dirname(__DIR__)
);
exit($check->run());
