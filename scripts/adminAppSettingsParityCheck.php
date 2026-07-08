<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class AdminAppSettingsParityCheck
{
    private const PREFIX = 'E2E_APP_CFG_';
    private const API_TOKEN = 'E2EApiToken1234567890_Ab';
    private const SDK_API_URL = 'https://sdk.example.test/api/v1/index.php';

    public function __construct(
        private readonly SpringMySQLi $database,
        private readonly string $systemKey,
        private readonly string $phpBaseUrl,
        private readonly string $rustBaseUrl
    ) {
    }

    public function run(): int
    {
        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $session = $this->createAdminSession();
            $phpResult = $this->runTarget('php', $this->phpBaseUrl, $session);
            $rustResult = $this->runTarget('rust', $this->rustBaseUrl, $session);
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'adminAppSettings');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK admin app settings\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function runTarget(string $name, string $baseUrl, array $session): array
    {
        $target = [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => self::PREFIX . strtoupper($name) . '_' . $this->randomAlpha(6),
        ];
        $steps = [];
        $steps['create'] = $this->normalizeCreate($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/create',
            [
                'app_code' => $target['appCode'],
                'name' => 'Parity App Settings',
                'client_crypto_alg' => 'rsa_oaep_aes_128_gcm',
                'remark' => 'created by admin app settings parity',
            ]
        )));
        $createdRow = $this->appRow($target, $session);
        $steps['createdApp'] = $this->normalizeApp($createdRow);
        $deviceInstallId = $this->insertBindIpDevice($target['appCode']);
        $steps['deviceBeforeSettings'] = $this->deviceBindFact($target['appCode'], $deviceInstallId);
        $steps['settingsIpOn'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/update',
            [
                'app_id' => $createdRow['id'],
                'name' => 'Parity App Settings Updated',
                'session_ttl_seconds' => 600,
                'heartbeat_enabled' => 0,
                'verification_enabled' => 0,
                'device_binding_enabled' => 0,
                'shared_cards_enabled' => 1,
                'login_ip_binding_enabled' => 1,
                'client_crypto_alg' => 'rsa_pkcs1_aes_256_gcm',
                'remark' => 'settings ip on',
            ]
        ));
        $steps['afterSettingsIpOn'] = $this->normalizeApp($this->appRow($target, $session));
        $steps['settingsIpOff'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/update',
            [
                'app_id' => $createdRow['id'],
                'name' => 'Parity App Settings Updated',
                'session_ttl_seconds' => 900,
                'heartbeat_enabled' => 1,
                'verification_enabled' => 1,
                'device_binding_enabled' => 1,
                'shared_cards_enabled' => 0,
                'login_ip_binding_enabled' => 0,
                'client_crypto_alg' => 'rsa_pkcs1_aes_256_gcm',
                'remark' => 'settings ip off',
            ]
        ));
        $steps['afterSettingsIpOff'] = $this->normalizeApp($this->appRow($target, $session));
        $steps['deviceAfterIpOff'] = $this->deviceBindFact($target['appCode'], $deviceInstallId);
        $steps['apiUpdate'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/api/update',
            [
                'app_id' => $createdRow['id'],
                'api_token' => self::API_TOKEN,
                'api_success_code' => 201,
                'web_card_query_enabled' => 1,
                'unbind_interval_seconds' => 1200,
                'unbind_deduct_seconds' => 60,
                'unbind_deduct_uses' => 3,
                'api_routes' => $this->apiRoutesPayload(),
            ]
        ));
        $steps['afterApiUpdate'] = $this->normalizeApp($this->appRow($target, $session));
        foreach ($this->runRemoteConfigChecks($target, $session) as $stepName => $stepData) {
            $steps[$stepName] = $stepData;
        }
        foreach ($this->runSdkChecks($target, $session) as $stepName => $stepData) {
            $steps[$stepName] = $stepData;
        }
        foreach ($this->runSecurityPolicyChecks($target, $session) as $stepName => $stepData) {
            $steps[$stepName] = $stepData;
        }
        foreach ($this->runDangerOperationChecks($target, $session) as $stepName => $stepData) {
            $steps[$stepName] = $stepData;
        }
        $steps['duplicateCallIdError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/api/update',
            [
                'app_id' => $createdRow['id'],
                'api_token' => self::API_TOKEN,
                'api_routes' => [
                    ['route' => '/login', 'call_id' => 'dup_call', 'enabled' => 1],
                    ['route' => '/heartbeat', 'call_id' => 'dup_call', 'enabled' => 1],
                ],
            ]
        ));
        return ['steps' => $steps];
    }

    private function runRemoteConfigChecks(array $target, array $session): array
    {
        $steps = [];
        $steps['remoteConfigEmpty'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/config/get',
            ['app_code' => $target['appCode']]
        ));
        $this->insertRemoteConfigArtifacts($target['appCode']);
        $steps['remoteConfigSeededRaw'] = $this->remoteConfigRawFact($target['appCode']);
        $steps['remoteConfigSaveTruthy'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/config/set',
            [
                'app_code' => $target['appCode'],
                'version' => '2.5.1',
                'download_url' => 'https://download.example.test/app.exe',
                'notice' => "第一行公告\n第二行公告",
                'force_update' => 'false',
            ]
        ));
        $steps['remoteConfigAfterTruthy'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/config/get',
            ['app_code' => $target['appCode']]
        ));
        $steps['remoteConfigRawAfterTruthy'] = $this->remoteConfigRawFact($target['appCode']);
        $steps['remoteConfigSaveZero'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/config/set',
            [
                'app_code' => $target['appCode'],
                'version' => '',
                'download_url' => '',
                'notice' => '',
                'force_update' => '0',
            ]
        ));
        $steps['remoteConfigAfterZero'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/config/get',
            ['app_code' => $target['appCode']]
        ));
        return $steps;
    }

    private function runSdkChecks(array $target, array $session): array
    {
        $steps = [];
        $steps['keypairRegenerate'] = $this->normalizeKeypair($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/generate-keypair',
            [
                'app_code' => $target['appCode'],
                'client_crypto_alg' => 'rsa_oaep_aes_256_gcm',
            ]
        )));
        $steps['afterKeypair'] = $this->normalizeApp($this->appRow($target, $session));
        $steps['integration'] = $this->normalizeIntegration($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/integration',
            [
                'app_code' => $target['appCode'],
                'api_url' => self::SDK_API_URL,
            ]
        )));
        $steps['sdkWindows'] = $this->normalizeSdkPackage($target, $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/sdk',
            [
                'app_code' => $target['appCode'],
                'api_url' => self::SDK_API_URL,
                'sdk_type' => 'windows',
            ]
        )), 'windows');
        $steps['sdkPythonAlias'] = $this->normalizeSdkPackage($target, $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/sdk',
            [
                'app_code' => $target['appCode'],
                'api_url' => self::SDK_API_URL,
                'sdk_type' => 'py',
            ]
        )), 'python');
        $steps['invalidSdkTypeError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/sdk',
            [
                'app_code' => $target['appCode'],
                'api_url' => self::SDK_API_URL,
                'sdk_type' => 'plan9',
            ]
        ));
        $steps['invalidSdkUrlError'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/apps/integration',
            [
                'app_code' => $target['appCode'],
                'api_url' => 'http://例子.测试/api',
            ]
        ));
        return $steps;
    }

    private function runSecurityPolicyChecks(array $target, array $session): array
    {
        $steps = [];
        $steps['securityPolicyEmpty'] = $this->normalizeSecurityPolicyData($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/security/policy/get',
            ['app_code' => $target['appCode']]
        )));
        $steps['securityPolicySaveFull'] = $this->normalizeSecurityPolicyData($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/security/policy/set',
            $this->securityPolicyFullPayload($target['appCode'])
        )));
        $steps['securityPolicyRawAfterFull'] = $this->securityPolicyRawFact($target['appCode']);
        $steps['securityPolicyAfterFull'] = $this->normalizeSecurityPolicyData($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/security/policy/get',
            ['app_code' => $target['appCode']]
        )));
        $steps['securityPolicySaveDefaults'] = $this->normalizeSecurityPolicyData($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/security/policy/set',
            ['app_code' => $target['appCode']]
        )));
        $steps['securityPolicyRawAfterDefaults'] = $this->securityPolicyRawFact($target['appCode']);
        $steps['securityPolicyAfterDefaults'] = $this->normalizeSecurityPolicyData($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/security/policy/get',
            ['app_code' => $target['appCode']]
        )));
        foreach ($this->securityPolicyErrorPayloads($target['appCode']) as $name => $payload) {
            $steps[$name] = $this->normalizeError($this->adminRequest(
                $target,
                $session,
                '/admin/security/policy/set',
                $payload
            ));
        }
        return $steps;
    }

    private function securityPolicyFullPayload(string $appCode): array
    {
        return [
            'app_code' => $appCode,
            'enabled' => true,
            'mode' => ' BOUNDED_CLIENT ',
            'min_confidence_for_client_action' => ' 75 ',
            'max_client_action' => ' DISABLE_DEVICE ',
            'kick_score' => '+81',
            'disable_device_score' => '96',
            'disable_card_score' => 121,
            'allowed_client_actions' => ['disable_card', ' KICK_SESSION ', 'record_only', 'kick_session', ''],
            'client_disable_device_min_score' => '+82',
            'client_disable_card_min_score' => ' 97 ',
            'report_rate_limit_per_minute' => '21',
            'report_retention_days' => 91,
            'message_retention_days' => '181',
            'server_critical_action' => 'DISABLE_CARD',
            'server_high_action' => ' disable_device ',
            'server_medium_action' => 'MANUAL_REVIEW',
            'server_low_action' => 'record_only',
            'trusted_event_types' => ['debugger_detected', 'hook_detected', 'debugger_detected', 'custom_event_1'],
        ];
    }

    private function securityPolicyErrorPayloads(string $appCode): array
    {
        return [
            'securityPolicyInvalidModeError' => ['app_code' => $appCode, 'mode' => 'unknown_mode'],
            'securityPolicyInvalidActionError' => ['app_code' => $appCode, 'max_client_action' => 'burn_device'],
            'securityPolicyInvalidTrustedListError' => ['app_code' => $appCode, 'trusted_event_types' => 'debugger_detected'],
            'securityPolicyInvalidTrustedValueError' => ['app_code' => $appCode, 'trusted_event_types' => ['AA']],
            'securityPolicyInvalidNumberError' => ['app_code' => $appCode, 'kick_score' => '081'],
        ];
    }

    private function runDangerOperationChecks(array $target, array $session): array
    {
        $steps = [];
        $this->seedAppActivityData($target['appCode']);
        $steps['appActivityBeforeClear'] = $this->appActivityFact($target['appCode']);
        $steps['clearAppActivity'] = $this->normalizeAppActivityCleanup($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/clear-app-activity',
            ['app_code' => $target['appCode']]
        )));
        $steps['appActivityAfterClear'] = $this->appActivityFact($target['appCode']);
        $this->seedMaintenanceCleanupData($target['appCode']);
        $steps['maintenanceBeforeCleanup'] = $this->maintenanceCleanupFact($target['appCode']);
        $steps['maintenanceCleanup'] = $this->normalizeMaintenanceCleanup($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/maintenance/cleanup-nonces',
            ['request' => 'cleanup']
        )));
        $steps['maintenanceAfterCleanup'] = $this->maintenanceCleanupFact($target['appCode']);
        return $steps;
    }

    private function normalizeAppActivityCleanup(array $data): array
    {
        return [
            'deleted_message_actions' => (int)($data['deleted_message_actions'] ?? -1),
            'deleted_messages' => (int)($data['deleted_messages'] ?? -1),
            'deleted_security_reports' => (int)($data['deleted_security_reports'] ?? -1),
            'deleted_audit_logs' => (int)($data['deleted_audit_logs'] ?? -1),
            'app_code_prefix_ok' => str_starts_with((string)($data['app_code'] ?? ''), self::PREFIX),
        ];
    }

    private function normalizeMaintenanceCleanup(array $data): array
    {
        $securityData = is_array($data['security_data'] ?? null) ? $data['security_data'] : [];
        return [
            'deleted_nonces_seeded' => (int)($data['deleted_nonces'] ?? 0) >= 1,
            'deleted_sessions_seeded' => (int)($data['deleted_sessions'] ?? 0) >= 1,
            'deleted_login_challenges_seeded' => (int)($data['deleted_login_challenges'] ?? 0) >= 2,
            'deleted_admin_nonces_seeded' => (int)($data['deleted_admin_nonces'] ?? 0) >= 1,
            'deleted_admin_sessions_seeded' => (int)($data['deleted_admin_sessions'] ?? 0) >= 1,
            'deleted_remote_api_nonces_seeded' => (int)($data['deleted_remote_api_nonces'] ?? 0) >= 1,
            'deleted_cloud_upload_tickets_seeded' => (int)($data['deleted_cloud_upload_tickets'] ?? 0) >= 1,
            'deleted_security_reports_seeded' => (int)($securityData['deleted_security_reports'] ?? 0) >= 1,
            'deleted_messages_seeded' => (int)($securityData['deleted_messages'] ?? 0) >= 2,
            'deleted_message_actions_seeded' => (int)($securityData['deleted_message_actions'] ?? 0) >= 1,
        ];
    }

    private function apiRoutesPayload(): array
    {
        return [
            ['route' => '/login', 'call_id' => 'login_ignored', 'enabled' => 0],
            ['route' => '/heartbeat', 'call_id' => 'heartbeat_custom', 'enabled' => 1],
            ['route' => '/config', 'call_id' => '', 'enabled' => 0],
            ['route' => '/unknown', 'call_id' => 'ignored_unknown', 'enabled' => 0],
            ['route' => '/login', 'call_id' => 'login_final', 'enabled' => 1],
        ];
    }

    private function normalizeCreate(array $data): array
    {
        return [
            'app_code_prefix_ok' => str_starts_with((string)($data['app_code'] ?? ''), self::PREFIX),
            'client_auth_mode' => $data['client_auth_mode'] ?? null,
            'client_crypto_alg' => $data['client_crypto_alg'] ?? null,
            'client_public_key_present' => str_contains((string)($data['client_public_key'] ?? ''), 'BEGIN PUBLIC KEY'),
        ];
    }

    private function normalizeApp(array $row): array
    {
        return [
            'name' => $row['name'] ?? null,
            'status' => (int)($row['status'] ?? -1),
            'max_devices' => (int)($row['max_devices'] ?? -1),
            'heartbeat_interval' => (int)($row['heartbeat_interval'] ?? -1),
            'heartbeat_enabled' => (int)($row['heartbeat_enabled'] ?? -1),
            'verification_enabled' => (int)($row['verification_enabled'] ?? -1),
            'device_binding_enabled' => (int)($row['device_binding_enabled'] ?? -1),
            'shared_cards_enabled' => (int)($row['shared_cards_enabled'] ?? -1),
            'login_ip_binding_enabled' => (int)($row['login_ip_binding_enabled'] ?? -1),
            'web_card_query_enabled' => (int)($row['web_card_query_enabled'] ?? -1),
            'unbind_interval_seconds' => (int)($row['unbind_interval_seconds'] ?? -1),
            'unbind_deduct_seconds' => (int)($row['unbind_deduct_seconds'] ?? -1),
            'unbind_deduct_uses' => (int)($row['unbind_deduct_uses'] ?? -1),
            'api_success_code' => (int)($row['api_success_code'] ?? -1),
            'api_token_matches' => (string)($row['api_token'] ?? '') === self::API_TOKEN,
            'client_auth_mode' => $row['client_auth_mode'] ?? null,
            'client_crypto_alg' => $row['client_crypto_alg'] ?? null,
            'client_public_key_present' => str_contains((string)($row['client_public_key'] ?? ''), 'BEGIN PUBLIC KEY'),
            'remark' => $row['remark'] ?? null,
            'api_routes' => $this->normalizeApiRoutes($row['api_routes'] ?? []),
        ];
    }

    private function normalizeApiRoutes(mixed $routes): array
    {
        $result = [];
        foreach (is_array($routes) ? $routes : [] as $route) {
            if (!is_array($route)) {
                continue;
            }
            $result[] = [
                'route' => (string)($route['route'] ?? ''),
                'call_id' => (string)($route['call_id'] ?? ''),
                'enabled' => (int)($route['enabled'] ?? -1),
            ];
        }
        return $result;
    }

    private function normalizeError(array $step): array
    {
        $body = is_array($step['body'] ?? null) ? $step['body'] : [];
        return [
            'httpStatus' => $step['httpStatus'] ?? 0,
            'code' => $body['code'] ?? null,
            'error' => $body['error'] ?? null,
        ];
    }

    private function normalizeKeypair(array $data): array
    {
        return [
            'app_code_prefix_ok' => str_starts_with((string)($data['app_code'] ?? ''), self::PREFIX),
            'client_crypto_alg' => (string)($data['client_crypto_alg'] ?? ''),
            'client_public_key_present' => str_contains((string)($data['client_public_key'] ?? ''), 'BEGIN PUBLIC KEY'),
        ];
    }

    private function normalizeIntegration(array $data): array
    {
        $app = is_array($data['app'] ?? null) ? $data['app'] : [];
        return [
            'api_url' => (string)($data['api_url'] ?? ''),
            'app' => [
                'app_code_prefix_ok' => str_starts_with((string)($app['app_code'] ?? ''), self::PREFIX),
                'api_token_matches' => (string)($app['api_token'] ?? '') === self::API_TOKEN,
                'api_success_code' => (int)($app['api_success_code'] ?? -1),
                'api_routes' => $this->normalizeApiRoutes($app['api_routes'] ?? []),
                'name' => (string)($app['name'] ?? ''),
                'client_auth_mode' => (string)($app['client_auth_mode'] ?? ''),
                'client_crypto_alg' => (string)($app['client_crypto_alg'] ?? ''),
                'client_public_key_present' => str_contains((string)($app['client_public_key'] ?? ''), 'BEGIN PUBLIC KEY'),
                'app_version' => (string)($app['app_version'] ?? ''),
                'heartbeat_interval' => (int)($app['heartbeat_interval'] ?? -1),
                'heartbeat_enabled' => (int)($app['heartbeat_enabled'] ?? -1),
                'verification_enabled' => (int)($app['verification_enabled'] ?? -1),
                'device_binding_enabled' => (int)($app['device_binding_enabled'] ?? -1),
                'shared_cards_enabled' => (int)($app['shared_cards_enabled'] ?? -1),
                'login_ip_binding_enabled' => (int)($app['login_ip_binding_enabled'] ?? -1),
                'web_card_query_enabled' => (int)($app['web_card_query_enabled'] ?? -1),
                'unbind_interval_seconds' => (int)($app['unbind_interval_seconds'] ?? -1),
                'unbind_deduct_seconds' => (int)($app['unbind_deduct_seconds'] ?? -1),
                'unbind_deduct_uses' => (int)($app['unbind_deduct_uses'] ?? -1),
            ],
            'sdk_types' => $this->normalizeValueLabelRows($data['sdk_types'] ?? []),
            'client_routes' => $this->normalizeRouteDocs($data['client_routes'] ?? []),
            'error_codes' => $this->normalizeErrorCodes($data['error_codes'] ?? []),
        ];
    }

    private function normalizeSdkPackage(array $target, array $data, string $sdkType): array
    {
        $archive = $this->sdkArchiveFacts($target, $data, $sdkType);
        return [
            'app_code_prefix_ok' => str_starts_with((string)($data['app_code'] ?? ''), self::PREFIX),
            'api_url' => (string)($data['api_url'] ?? ''),
            'filename' => (string)($data['filename'] ?? ''),
            'mime' => (string)($data['mime'] ?? ''),
            'size_positive' => (int)($data['size'] ?? 0) > 0,
            'content_size_matches' => $archive['content_size_matches'],
            'reported_files_match_zip' => $archive['reported_files_match_zip'],
            'files' => $archive['files'],
            'placeholders_removed' => $archive['placeholders_removed'],
            'config_has_api_url' => $archive['config_has_api_url'],
            'config_has_app_code' => $archive['config_has_app_code'],
            'config_has_api_token' => $archive['config_has_api_token'],
            'config_has_success_code' => $archive['config_has_success_code'],
            'config_has_crypto_alg' => $archive['config_has_crypto_alg'],
            'config_has_public_key' => $archive['config_has_public_key'],
            'cloud_ticket_extra_expectation_met' => $archive['cloud_ticket_extra_expectation_met'],
            'third_party_excluded' => $archive['third_party_excluded'],
        ];
    }

    private function sdkArchiveFacts(array $target, array $data, string $sdkType): array
    {
        $bytes = base64_decode((string)($data['content_base64'] ?? ''), true);
        if (!is_string($bytes)) {
            throw new RuntimeException('SDK content_base64 decode failed');
        }
        $zipPath = tempnam(__DIR__, 'sdkzip_');
        if (!is_string($zipPath)) {
            throw new RuntimeException('SDK temp file create failed');
        }
        try {
            file_put_contents($zipPath, $bytes);
            $zip = new ZipArchive();
            if ($zip->open($zipPath) !== true) {
                throw new RuntimeException('SDK zip open failed');
            }
            try {
                return $this->readSdkArchiveFacts($target, $data, $sdkType, $zip, $bytes);
            } finally {
                $zip->close();
            }
        } finally {
            @unlink($zipPath);
        }
    }

    private function readSdkArchiveFacts(array $target, array $data, string $sdkType, ZipArchive $zip, string $bytes): array
    {
        $files = $this->zipFileNames($zip);
        $configContent = $this->sdkConfigContent($zip, $sdkType);
        $clientContent = $this->sdkClientContent($zip, $sdkType);
        $reportedFiles = array_values(array_map('strval', is_array($data['files'] ?? null) ? $data['files'] : []));
        sort($reportedFiles);
        return [
            'content_size_matches' => strlen($bytes) === (int)($data['size'] ?? -1),
            'reported_files_match_zip' => $reportedFiles === $files,
            'files' => $files,
            'placeholders_removed' => !str_contains($configContent . $clientContent, '{{Sdk'),
            'config_has_api_url' => str_contains($configContent, self::SDK_API_URL),
            'config_has_app_code' => str_contains($configContent, $target['appCode']),
            'config_has_api_token' => str_contains($configContent, self::API_TOKEN),
            'config_has_success_code' => str_contains($configContent, '201'),
            'config_has_crypto_alg' => str_contains($configContent, 'rsa_oaep_aes_256_gcm'),
            'config_has_public_key' => str_contains($configContent, 'BEGIN PUBLIC KEY'),
            'cloud_ticket_extra_expectation_met' => $this->cloudTicketExtraExpectationMet($target, $clientContent),
            'third_party_excluded' => !$this->hasPathPrefix($files, 'third_party/'),
        ];
    }

    private function zipFileNames(ZipArchive $zip): array
    {
        $files = [];
        for ($index = 0; $index < $zip->numFiles; $index++) {
            $name = $zip->getNameIndex($index);
            if (is_string($name)) {
                $files[] = $name;
            }
        }
        sort($files);
        return $files;
    }

    private function sdkConfigContent(ZipArchive $zip, string $sdkType): string
    {
        $path = $sdkType === 'python' ? 'licenseauth/config.py' : 'include/AuthConfig.hpp';
        $content = $zip->getFromName($path);
        if (!is_string($content)) {
            throw new RuntimeException("SDK config missing: {$path}");
        }
        return $content;
    }

    private function sdkClientContent(ZipArchive $zip, string $sdkType): string
    {
        $path = $sdkType === 'python' ? 'licenseauth/client.py' : 'src/AuthClient.cpp';
        $content = $zip->getFromName($path);
        if (!is_string($content)) {
            throw new RuntimeException("SDK client missing: {$path}");
        }
        return $content;
    }

    private function cloudTicketExtraExpectationMet(array $target, string $clientContent): bool
    {
        $hasFileKeyExtra = str_contains($clientContent, '"/cloud/download-ticket"')
            && str_contains($clientContent, 'file_key');
        return $target['name'] === 'rust' ? $hasFileKeyExtra : !$hasFileKeyExtra;
    }

    private function hasPathPrefix(array $files, string $prefix): bool
    {
        foreach ($files as $file) {
            if (str_starts_with((string)$file, $prefix)) {
                return true;
            }
        }
        return false;
    }

    private function normalizeValueLabelRows(mixed $rows): array
    {
        $result = [];
        foreach (is_array($rows) ? $rows : [] as $row) {
            if (!is_array($row)) {
                continue;
            }
            $result[] = [
                'value' => (string)($row['value'] ?? ''),
                'label' => (string)($row['label'] ?? ''),
            ];
        }
        return $result;
    }

    private function normalizeRouteDocs(mixed $rows): array
    {
        $result = [];
        foreach (is_array($rows) ? $rows : [] as $row) {
            if (!is_array($row)) {
                continue;
            }
            $result[] = [
                'route' => (string)($row['route'] ?? ''),
                'method' => (string)($row['method'] ?? ''),
                'name' => (string)($row['name'] ?? ''),
                'auth' => (string)($row['auth'] ?? ''),
            ];
        }
        return $result;
    }

    private function normalizeErrorCodes(mixed $rows): array
    {
        $result = [];
        foreach (is_array($rows) ? $rows : [] as $row) {
            if (!is_array($row)) {
                continue;
            }
            $result[] = [
                'code' => (string)($row['code'] ?? ''),
                'message' => (string)($row['message'] ?? ''),
            ];
        }
        return $result;
    }

    private function normalizeSecurityPolicyData(array $data): array
    {
        return [
            'saved' => array_key_exists('saved', $data) ? (bool)$data['saved'] : null,
            'policy' => $this->normalizeSecurityPolicy(is_array($data['policy'] ?? null) ? $data['policy'] : []),
        ];
    }

    private function normalizeSecurityPolicy(array $policy): array
    {
        return [
            'enabled' => (int)($policy['enabled'] ?? -1),
            'mode' => (string)($policy['mode'] ?? ''),
            'min_confidence_for_client_action' => (int)($policy['min_confidence_for_client_action'] ?? -1),
            'max_client_action' => (string)($policy['max_client_action'] ?? ''),
            'kick_score' => (int)($policy['kick_score'] ?? -1),
            'disable_device_score' => (int)($policy['disable_device_score'] ?? -1),
            'disable_card_score' => (int)($policy['disable_card_score'] ?? -1),
            'allowed_client_actions' => array_values(array_map('strval', is_array($policy['allowed_client_actions'] ?? null) ? $policy['allowed_client_actions'] : [])),
            'client_disable_device_min_score' => (int)($policy['client_disable_device_min_score'] ?? -1),
            'client_disable_card_min_score' => (int)($policy['client_disable_card_min_score'] ?? -1),
            'report_rate_limit_per_minute' => (int)($policy['report_rate_limit_per_minute'] ?? -1),
            'report_retention_days' => (int)($policy['report_retention_days'] ?? -1),
            'message_retention_days' => (int)($policy['message_retention_days'] ?? -1),
            'server_critical_action' => (string)($policy['server_critical_action'] ?? ''),
            'server_high_action' => (string)($policy['server_high_action'] ?? ''),
            'server_medium_action' => (string)($policy['server_medium_action'] ?? ''),
            'server_low_action' => (string)($policy['server_low_action'] ?? ''),
            'trusted_event_types' => array_values(array_map('strval', is_array($policy['trusted_event_types'] ?? null) ? $policy['trusted_event_types'] : [])),
            'updated_by_state' => $this->adminActorState((string)($policy['updated_by'] ?? '')),
            'updated_at_state' => trim((string)($policy['updated_at'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function appRow(array $target, array $session): array
    {
        $data = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/apps/list',
            ['page' => 1, 'limit' => 100]
        ));
        foreach (($data['apps'] ?? []) as $row) {
            if (is_array($row) && ($row['app_code'] ?? '') === $target['appCode']) {
                return $row;
            }
        }
        throw new RuntimeException('created app not found in list: ' . $target['appCode']);
    }

    private function adminRequest(array $target, array $session, string $route, array $payload): array
    {
        $timestamp = (string)time();
        $nonce = Crypto::token(18);
        $plaintext = $this->json($payload);
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
                'timeout' => 10,
            ],
        ]);
        $raw = @file_get_contents($url, false, $context);
        $body = json_decode(is_string($raw) ? $raw : '', true);
        return [
            'httpStatus' => $this->httpStatus($http_response_header ?? []),
            'body' => is_array($body) ? $body : ['error' => 'NON_JSON_RESPONSE', 'raw' => $raw],
        ];
    }

    private function successData(array $step): array
    {
        $body = $step['body'];
        if (($step['httpStatus'] ?? 0) !== 200 || !is_array($body) || ($body['code'] ?? null) !== 0) {
            throw new RuntimeException('admin request failed: ' . $this->json($step));
        }
        $data = $body['data'] ?? [];
        if (!is_array($data)) {
            throw new RuntimeException('admin response data is not object: ' . $this->json($step));
        }
        return $data;
    }

    private function createAdminSession(): array
    {
        $username = self::PREFIX . 'admin_' . strtolower($this->randomAlpha(6));
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity App Settings Admin', $this->rustBaseUrl]
        );
        $token = Crypto::token();
        $keyText = Crypto::encodeBase64Url(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', time() + 3600);
        $this->exec(
            'INSERT INTO `auth_admin_sessions` (`token_hash`, `key_cipher`, `ip`, `admin_username`, `expires_at`, `status`) VALUES (?, ?, ?, ?, ?, ?)',
            [Crypto::sha256($token), Crypto::encryptSecret($keyText, $this->systemKey), '127.0.0.1', $username, $expiresAt, 1]
        );
        return [
            'token' => $token,
            'rawKey' => Crypto::decodeBase64Url($keyText),
        ];
    }

    private function insertBindIpDevice(string $appCode): string
    {
        $appId = $this->appId($appCode);
        $installId = 'INSTALL_' . strtoupper(substr(hash('sha256', $appCode . ':bind-ip'), 0, 24));
        $this->exec(
            'INSERT INTO `auth_devices` (`app_id`, `account_id`, `card_id`, `card_hash`, `device_hash`, `device_name`, `install_id`, `device_public_key`, `device_key_alg`, `machine_profile_hash`, `bind_ip`, `bind_region`, `risk_level`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                null,
                null,
                '',
                hash('sha256', $appCode . ':device'),
                'Parity App Settings Device',
                $installId,
                '',
                'local_key_v1',
                hash('sha256', $appCode . ':machine'),
                '127.0.0.1',
                'Local',
                0,
                1,
            ]
        );
        return $installId;
    }

    private function deviceBindFact(string $appCode, string $installId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `bind_ip`, `bind_region` FROM `auth_devices` WHERE `app_id` = ? AND `install_id` = ?',
            [$this->appId($appCode), $installId]
        );
        if (!is_array($row)) {
            return ['exists' => false];
        }
        return [
            'exists' => true,
            'bind_ip' => (string)($row['bind_ip'] ?? ''),
            'bind_region' => (string)($row['bind_region'] ?? ''),
        ];
    }

    private function insertRemoteConfigArtifacts(string $appCode): void
    {
        $this->exec(
            'INSERT INTO `auth_remote_configs` (`app_id`, `notice`, `config_json`, `variables_json`, `version`, `force_update`, `download_url`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $this->appId($appCode),
                'seed notice',
                '{"kept":"config"}',
                '{"kept":"variables"}',
                'seed-version',
                0,
                'https://seed.example.test/download',
                1,
            ]
        );
    }

    private function remoteConfigRawFact(string $appCode): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `config_json`, `variables_json`, `status` FROM `auth_remote_configs` WHERE `app_id` = ?',
            [$this->appId($appCode)]
        );
        if (!is_array($row)) {
            return ['exists' => false];
        }
        return [
            'exists' => true,
            'config_json' => (string)($row['config_json'] ?? ''),
            'variables_json' => (string)($row['variables_json'] ?? ''),
            'status' => (int)($row['status'] ?? -1),
        ];
    }

    private function seedAppActivityData(string $appCode): void
    {
        $appId = $this->appId($appCode);
        $this->deleteAppActivityRows($appId);
        $reportId = (int)$this->exec(
            'INSERT INTO `auth_security_reports` (`app_id`, `event_id`, `event_type`, `risk_level`, `confidence`, `requested_action`, `action`, `action_source`, `risk_score`, `action_reason`, `title`, `message`, `evidence_json`, `attestation_json`, `occurred_at`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, self::PREFIX . 'activity_event', 'debugger_detected', 'high', 88, 'manual_review', 'manual_review', 'client', 88, 'seed', 'activity report', 'activity message', '{}', '{}', '2000-01-01 00:00:00', '2000-01-01 00:00:00']
        );
        $messageId = (int)$this->exec(
            'INSERT INTO `auth_messages` (`app_id`, `report_id`, `message_type`, `severity`, `status`, `title`, `summary`, `action`, `action_source`, `risk_score`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, $reportId, 'security_report', 'high', 'unread', self::PREFIX . 'activity message 1', 'seed activity message 1', 'manual_review', 'client', 88, '2000-01-01 00:00:00']
        );
        $this->exec(
            'INSERT INTO `auth_messages` (`app_id`, `message_type`, `severity`, `status`, `title`, `summary`, `action`, `action_source`, `risk_score`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, 'security_report', 'low', 'archived', self::PREFIX . 'activity message 2', 'seed activity message 2', 'record_only', 'client', 12, '2000-01-01 00:00:00']
        );
        $this->exec(
            'INSERT INTO `auth_message_actions` (`app_id`, `message_id`, `action`, `actor_type`, `actor_name`, `result`, `remark`, `ip`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, $messageId, 'manual_review', 'admin', self::PREFIX . 'activity_actor', 'success', 'seed activity action', '127.0.0.1']
        );
        for ($index = 1; $index <= 3; $index++) {
            $this->exec(
                'INSERT INTO `auth_audit_logs` (`app_id`, `account_id`, `action`, `message`, `ip`, `region`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [$appId, null, 'activity_seed', self::PREFIX . 'activity audit ' . $index, '127.0.0.1', 'Local', '2000-01-01 00:00:00']
            );
        }
    }

    private function appActivityFact(string $appCode): array
    {
        $appId = $this->appId($appCode);
        return [
            'message_actions' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_message_actions` WHERE `app_id` = ?', [$appId]),
            'messages' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_messages` WHERE `app_id` = ?', [$appId]),
            'security_reports' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_security_reports` WHERE `app_id` = ?', [$appId]),
            'audit_logs' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_audit_logs` WHERE `app_id` = ?', [$appId]),
        ];
    }

    private function seedMaintenanceCleanupData(string $appCode): void
    {
        $this->deleteMaintenanceSeedRows($appCode);
        $appId = $this->appId($appCode);
        $past = '2000-01-01 00:00:00';
        $future = date('Y-m-d H:i:s', time() + 86400);
        $this->exec('INSERT INTO `auth_nonces` (`app_id`, `nonce_hash`, `expires_at`) VALUES (?, ?, ?)', [$appId, $this->seedHash($appCode, 'nonce'), $past]);
        $this->exec('INSERT INTO `auth_sessions` (`app_id`, `card_hash`, `card_fingerprint`, `token_hash`, `proof_mode`, `status`, `ip`, `expires_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [$appId, $this->seedHash($appCode, 'card'), 'E2E', $this->seedHash($appCode, 'session'), 'local_key_v1', 1, '127.0.0.1', $past]);
        $this->exec('INSERT INTO `auth_login_challenges` (`app_id`, `install_id`, `challenge_id`, `server_nonce`, `expires_at`) VALUES (?, ?, ?, ?, ?)', [$appId, self::PREFIX . 'install_expired', self::PREFIX . $this->seedShort($appCode, 'challenge-expired'), 'server_nonce', $past]);
        $this->exec('INSERT INTO `auth_login_challenges` (`app_id`, `install_id`, `challenge_id`, `server_nonce`, `expires_at`, `used_at`) VALUES (?, ?, ?, ?, ?, ?)', [$appId, self::PREFIX . 'install_used', self::PREFIX . $this->seedShort($appCode, 'challenge-used'), 'server_nonce_used', $future, $past]);
        $adminSessionId = (int)$this->exec('INSERT INTO `auth_admin_sessions` (`token_hash`, `key_cipher`, `ip`, `admin_username`, `expires_at`, `status`) VALUES (?, ?, ?, ?, ?, ?)', [$this->seedHash($appCode, 'admin-session'), 'seed-key-cipher', '127.0.0.1', self::PREFIX . 'expired_admin_' . $this->seedShort($appCode, 'admin'), $past, 1]);
        $this->exec('INSERT INTO `auth_admin_nonces` (`session_id`, `nonce_hash`, `expires_at`) VALUES (?, ?, ?)', [$adminSessionId, $this->seedHash($appCode, 'admin-nonce'), $past]);
        $remoteTokenId = (int)$this->exec('INSERT INTO `auth_remote_api_tokens` (`name`, `access_key`, `secret_cipher`, `status`, `created_by`) VALUES (?, ?, ?, ?, ?)', [self::PREFIX . 'remote_cleanup_' . $this->seedShort($appCode, 'remote-name'), $this->remoteAccessKey($appCode), 'seed-secret-cipher', 1, self::PREFIX . 'tester']);
        $this->exec('INSERT INTO `auth_remote_api_nonces` (`token_id`, `nonce_hash`, `expires_at`) VALUES (?, ?, ?)', [$remoteTokenId, $this->seedHash($appCode, 'remote-nonce'), $past]);
        $this->exec('INSERT INTO `auth_cloud_upload_tickets` (`ticket_hash`, `provider`, `expected_sha256`, `expected_size`, `original_name`, `mime_type`, `remark`, `status`, `expires_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [$this->seedHash($appCode, 'cloud-ticket'), 'local', '', 0, self::PREFIX . 'expired-upload.bin', 'application/octet-stream', self::PREFIX . 'maintenance', 'pending', $past]);
        $this->seedMaintenanceSecurityRows($appId, $appCode, $past);
    }

    private function seedMaintenanceSecurityRows(int $appId, string $appCode, string $past): void
    {
        $this->exec('INSERT INTO `auth_security_reports` (`app_id`, `event_id`, `event_type`, `risk_level`, `confidence`, `requested_action`, `action`, `action_source`, `risk_score`, `action_reason`, `title`, `message`, `evidence_json`, `attestation_json`, `occurred_at`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [$appId, self::PREFIX . $this->seedShort($appCode, 'cleanup-report'), 'hook_detected', 'medium', 66, 'record_only', 'record_only', 'client', 66, 'seed cleanup', 'cleanup report', 'cleanup report message', '{}', '{}', $past, $past]);
        $messageId = (int)$this->exec('INSERT INTO `auth_messages` (`app_id`, `message_type`, `severity`, `status`, `title`, `summary`, `action`, `action_source`, `risk_score`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [$appId, 'security_report', 'low', 'archived', self::PREFIX . 'cleanup message low', 'seed cleanup low', 'record_only', 'client', 11, $past]);
        $this->exec('INSERT INTO `auth_messages` (`app_id`, `message_type`, `severity`, `status`, `title`, `summary`, `action`, `action_source`, `risk_score`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [$appId, 'security_report', 'critical', 'handled', self::PREFIX . 'cleanup message critical', 'seed cleanup critical', 'manual_review', 'server', 96, $past]);
        $this->exec('INSERT INTO `auth_message_actions` (`app_id`, `message_id`, `action`, `actor_type`, `actor_name`, `result`, `remark`, `ip`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [$appId, $messageId, 'record_only', 'system', self::PREFIX . 'cleanup_actor', 'success', 'seed cleanup action', '127.0.0.1']);
    }

    private function maintenanceCleanupFact(string $appCode): array
    {
        $appId = $this->appId($appCode);
        return [
            'nonces' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_nonces` WHERE `nonce_hash` = ?', [$this->seedHash($appCode, 'nonce')]),
            'sessions' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_sessions` WHERE `token_hash` = ?', [$this->seedHash($appCode, 'session')]),
            'login_challenges' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_login_challenges` WHERE `challenge_id` IN (?, ?)', [self::PREFIX . $this->seedShort($appCode, 'challenge-expired'), self::PREFIX . $this->seedShort($appCode, 'challenge-used')]),
            'admin_sessions' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_admin_sessions` WHERE `token_hash` = ?', [$this->seedHash($appCode, 'admin-session')]),
            'admin_nonces' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_admin_nonces` WHERE `nonce_hash` = ?', [$this->seedHash($appCode, 'admin-nonce')]),
            'remote_api_nonces' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_remote_api_nonces` WHERE `nonce_hash` = ?', [$this->seedHash($appCode, 'remote-nonce')]),
            'cloud_upload_tickets' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_cloud_upload_tickets` WHERE `ticket_hash` = ?', [$this->seedHash($appCode, 'cloud-ticket')]),
            'security_reports' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_security_reports` WHERE `app_id` = ? AND `event_id` = ?', [$appId, self::PREFIX . $this->seedShort($appCode, 'cleanup-report')]),
            'messages' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_messages` WHERE `app_id` = ? AND `title` LIKE ?', [$appId, self::PREFIX . 'cleanup message%']),
            'message_actions' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_message_actions` WHERE `app_id` = ? AND `actor_name` = ?', [$appId, self::PREFIX . 'cleanup_actor']),
        ];
    }

    private function deleteAppActivityRows(int $appId): void
    {
        foreach (['auth_message_actions', 'auth_messages', 'auth_security_reports', 'auth_audit_logs'] as $table) {
            $this->exec("DELETE FROM `{$table}` WHERE `app_id` = ?", [$appId]);
        }
    }

    private function deleteMaintenanceSeedRows(string $appCode): void
    {
        $appId = $this->appId($appCode);
        $this->exec('DELETE FROM `auth_message_actions` WHERE `app_id` = ? AND `actor_name` = ?', [$appId, self::PREFIX . 'cleanup_actor']);
        $this->exec('DELETE FROM `auth_messages` WHERE `app_id` = ? AND `title` LIKE ?', [$appId, self::PREFIX . 'cleanup message%']);
        $this->exec('DELETE FROM `auth_security_reports` WHERE `app_id` = ? AND `event_id` = ?', [$appId, self::PREFIX . $this->seedShort($appCode, 'cleanup-report')]);
        $this->exec('DELETE FROM `auth_nonces` WHERE `nonce_hash` = ?', [$this->seedHash($appCode, 'nonce')]);
        $this->exec('DELETE FROM `auth_sessions` WHERE `token_hash` = ?', [$this->seedHash($appCode, 'session')]);
        $this->exec('DELETE FROM `auth_login_challenges` WHERE `challenge_id` IN (?, ?)', [self::PREFIX . $this->seedShort($appCode, 'challenge-expired'), self::PREFIX . $this->seedShort($appCode, 'challenge-used')]);
        $this->exec('DELETE FROM `auth_admin_nonces` WHERE `nonce_hash` = ?', [$this->seedHash($appCode, 'admin-nonce')]);
        $this->exec('DELETE FROM `auth_admin_sessions` WHERE `token_hash` = ?', [$this->seedHash($appCode, 'admin-session')]);
        $this->exec('DELETE FROM `auth_remote_api_nonces` WHERE `nonce_hash` = ?', [$this->seedHash($appCode, 'remote-nonce')]);
        $this->exec('DELETE FROM `auth_remote_api_tokens` WHERE `access_key` = ?', [$this->remoteAccessKey($appCode)]);
        $this->exec('DELETE FROM `auth_cloud_upload_tickets` WHERE `ticket_hash` = ?', [$this->seedHash($appCode, 'cloud-ticket')]);
    }

    private function seedHash(string $appCode, string $suffix): string
    {
        return hash('sha256', $appCode . ':' . $suffix);
    }

    private function seedShort(string $appCode, string $suffix): string
    {
        return strtoupper(substr($this->seedHash($appCode, $suffix), 0, 24));
    }

    private function remoteAccessKey(string $appCode): string
    {
        return 'E2EAK' . $this->seedShort($appCode, 'remote-access-key');
    }

    private function securityPolicyRawFact(string $appCode): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `enabled`, `mode`, `min_confidence_for_client_action`, `max_client_action`, `kick_score`, `disable_device_score`, `disable_card_score`, `allowed_client_actions`, `client_disable_device_min_score`, `client_disable_card_min_score`, `report_rate_limit_per_minute`, `report_retention_days`, `message_retention_days`, `server_critical_action`, `server_high_action`, `server_medium_action`, `server_low_action`, `trusted_event_types_json`, `updated_by`, `updated_at` FROM `auth_security_policies` WHERE `app_id` = ?',
            [$this->appId($appCode)]
        );
        if (!is_array($row)) {
            return ['exists' => false];
        }
        return [
            'exists' => true,
            'enabled' => (int)($row['enabled'] ?? -1),
            'mode' => (string)($row['mode'] ?? ''),
            'min_confidence_for_client_action' => (int)($row['min_confidence_for_client_action'] ?? -1),
            'max_client_action' => (string)($row['max_client_action'] ?? ''),
            'kick_score' => (int)($row['kick_score'] ?? -1),
            'disable_device_score' => (int)($row['disable_device_score'] ?? -1),
            'disable_card_score' => (int)($row['disable_card_score'] ?? -1),
            'allowed_client_actions' => (string)($row['allowed_client_actions'] ?? ''),
            'client_disable_device_min_score' => (int)($row['client_disable_device_min_score'] ?? -1),
            'client_disable_card_min_score' => (int)($row['client_disable_card_min_score'] ?? -1),
            'report_rate_limit_per_minute' => (int)($row['report_rate_limit_per_minute'] ?? -1),
            'report_retention_days' => (int)($row['report_retention_days'] ?? -1),
            'message_retention_days' => (int)($row['message_retention_days'] ?? -1),
            'server_critical_action' => (string)($row['server_critical_action'] ?? ''),
            'server_high_action' => (string)($row['server_high_action'] ?? ''),
            'server_medium_action' => (string)($row['server_medium_action'] ?? ''),
            'server_low_action' => (string)($row['server_low_action'] ?? ''),
            'trusted_event_types_json' => (string)($row['trusted_event_types_json'] ?? ''),
            'updated_by_state' => $this->adminActorState((string)($row['updated_by'] ?? '')),
            'updated_at_state' => trim((string)($row['updated_at'] ?? '')) === '' ? 'empty' : 'present',
        ];
    }

    private function appId(string $appCode): int
    {
        $row = $this->database->selectRowV2('SELECT `id` FROM `auth_apps` WHERE `app_code` = ?', [$appCode]);
        if (!is_array($row) || !isset($row['id'])) {
            throw new RuntimeException("missing app {$appCode}");
        }
        return (int)$row['id'];
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
        $this->deleteGlobalTestRows();
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . '%']);
        foreach ($rows as $row) {
            $this->deleteAppRows((int)$row['id']);
        }
        $this->exec('DELETE FROM `sub_admin` WHERE `username` LIKE ?', [self::PREFIX . '%']);
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

    private function deleteGlobalTestRows(): void
    {
        if ($this->tableExists('auth_remote_api_tokens')) {
            $tokens = $this->database->selectV2('SELECT `id` FROM `auth_remote_api_tokens` WHERE `name` LIKE ? OR `access_key` LIKE ?', [self::PREFIX . '%', 'E2EAK%']);
            foreach ($tokens as $token) {
                if ($this->tableExists('auth_remote_api_nonces')) {
                    $this->exec('DELETE FROM `auth_remote_api_nonces` WHERE `token_id` = ?', [(int)$token['id']]);
                }
            }
            $this->exec('DELETE FROM `auth_remote_api_tokens` WHERE `name` LIKE ? OR `access_key` LIKE ?', [self::PREFIX . '%', 'E2EAK%']);
        }
        if ($this->tableExists('auth_cloud_upload_tickets')) {
            $this->exec('DELETE FROM `auth_cloud_upload_tickets` WHERE `original_name` LIKE ? OR `remark` LIKE ?', [self::PREFIX . '%', self::PREFIX . '%']);
        }
    }

    private function deleteAppRows(int $appId): void
    {
        foreach ([
            'auth_message_actions',
            'auth_messages',
            'auth_security_reports',
            'auth_security_policies',
            'auth_audit_logs',
            'auth_sessions',
            'auth_devices',
            'auth_accounts',
            'auth_login_challenges',
            'auth_card_search_tokens',
            'auth_cards',
            'auth_remote_configs',
        ] as $table) {
            if ($this->tableExists($table)) {
                $this->exec("DELETE FROM `{$table}` WHERE `app_id` = ?", [$appId]);
            }
        }
        $this->exec('DELETE FROM `auth_apps` WHERE `id` = ?', [$appId]);
    }

    private function printResult(string $name, array $result): void
    {
        echo strtoupper($name) . " " . $this->json($result) . "\n";
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
            return [$path . ' php=' . $this->json($left) . ' rust=' . $this->json($right)];
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

    private function adminActorState(string $username): string
    {
        if ($username === '') {
            return 'empty';
        }
        return str_starts_with($username, self::PREFIX . 'admin_') ? 'parity_admin' : 'other';
    }

    private function countRows(string $sql, array $params): int
    {
        $row = $this->database->selectRowV2($sql, $params);
        if (!is_array($row)) {
            return -1;
        }
        return (int)($row['c'] ?? -1);
    }

    private function exec(string $sql, array $params): int|string
    {
        $result = $this->database->exec($sql, $params);
        if ($result === false) {
            throw new RuntimeException($this->database->getError() ?: 'database statement failed');
        }
        return $result;
    }

    private function tableExists(string $tableName): bool
    {
        return is_array($this->database->selectRowV2('SHOW TABLES LIKE ?', [$tableName]));
    }

    private function json(mixed $value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            throw new RuntimeException('json encode failed');
        }
        return $json;
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

$check = new AdminAppSettingsParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
