<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
$rustProjectRoot = dirname(__DIR__);

require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Support\CardKeyFactory;
use NetworkAuth\Support\CardSearchIndex;
use NetworkAuth\Support\ClientApiConfig;

final class ClientSessionParityCheck
{
    private const APP_PREFIX = 'E2E_PARITY_';
    private const VARIABLE_PREFIX = 'e2e.parity.';
    private const FILE_PREFIX = 'E2EFILEPARITY';
    private const OBJECT_PREFIX = 'e2e/parity/';
    private const SESSION_ROUTES = [
        '/heartbeat' => 'heartbeat',
        '/config' => 'config',
        '/variable' => 'variable',
        '/cloud/download-ticket' => 'cloud_download_ticket',
        '/security/report' => 'security_report',
        '/logout' => 'logout',
    ];
    private const SECURITY_ACTION_BRANCHES = [
        'kick_session',
        'disable_device',
        'disable_card',
    ];

    private array $createdLocalConfigIds = [];
    private array $objectKeys = [];

    public function __construct(
        private readonly SpringMySQLi $database,
        private readonly string $systemKey,
        private readonly string $phpProjectRoot,
        private readonly string $rustProjectRoot,
        private readonly string $phpBaseUrl,
        private readonly string $rustBaseUrl
    ) {
    }

    public function run(): int
    {
        $keepData = in_array('--keep-data', $_SERVER['argv'] ?? [], true);
        $this->cleanup();
        try {
            $localConfigId = $this->ensureLocalStorageConfig();
            $phpTarget = $this->createTarget('php', $this->phpBaseUrl, $localConfigId);
            $rustTarget = $this->createTarget('rust', $this->rustBaseUrl, $localConfigId);
            $phpResult = $this->runTarget($phpTarget);
            $rustResult = $this->runTarget($rustTarget);
            $this->printTargetResult($phpResult);
            $this->printTargetResult($rustResult);
            $diffs = $this->compareResults($phpResult, $rustResult, 'main');
            foreach (self::SECURITY_ACTION_BRANCHES as $action) {
                $phpActionResult = $this->runActionTarget($this->createTarget('php_' . $action, $this->phpBaseUrl, $localConfigId), $action);
                $rustActionResult = $this->runActionTarget($this->createTarget('rust_' . $action, $this->rustBaseUrl, $localConfigId), $action);
                $this->printTargetResult($phpActionResult);
                $this->printTargetResult($rustActionResult);
                $diffs = array_merge(
                    $diffs,
                    $this->compareResults($phpActionResult, $rustActionResult, 'securityActions.' . $action),
                    $this->actionExpectationDiffs('php', $action, $phpActionResult),
                    $this->actionExpectationDiffs('rust', $action, $rustActionResult)
                );
            }
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK client plain session success path and security actions\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl, int $localConfigId): array
    {
        $suffix = strtoupper($name) . $this->randomAlpha(10);
        $namePart = substr(preg_replace('/[^A-Z0-9_]/', '_', strtoupper($name)) ?: 'TARGET', 0, 8);
        $appCode = self::APP_PREFIX . $namePart . '_' . $this->randomAlpha(8);
        $apiToken = ClientApiConfig::generateToken();
        $cardKey = 'CARD' . $this->randomAlpha(28);
        $variableName = self::VARIABLE_PREFIX . strtolower($suffix);
        $fileKey = self::FILE_PREFIX . $this->randomAlpha(24);
        $objectKey = self::OBJECT_PREFIX . strtolower($fileKey) . '.txt';
        $fileContent = "client session parity payload\n";
        $this->insertApp($appCode, $apiToken);
        $appId = $this->insertedId('auth_apps', 'app_code', $appCode);
        $this->insertCard($appId, $appCode, $cardKey);
        $this->insertRemoteConfig($appId);
        $this->insertRemoteVariable($variableName, 'plain-variable-value');
        $this->insertCloudFile($fileKey, $objectKey, $localConfigId, $fileContent);
        $this->writeLocalObject($objectKey, $fileContent);
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => $appCode,
            'apiToken' => $apiToken,
            'cardKey' => $cardKey,
            'installId' => 'INSTALL' . $this->randomAlpha(24),
            'machineProfileHash' => bin2hex(random_bytes(32)),
            'variableName' => $variableName,
            'fileKey' => $fileKey,
            'fileSha256' => hash('sha256', $fileContent),
        ];
    }

    private function runTarget(array $target): array
    {
        $state = ['counter' => 1, 'token' => '', 'sessionTicket' => ''];
        $steps = [];
        $steps['notice'] = $this->requestStep($target, '/notice', 'notice', []);
        $steps['loginChallenge'] = $this->requestStep($target, '/login/challenge', 'login_challenge', [
            'install_id' => $target['installId'],
            'device_name' => 'Parity Device',
            'device_key_mode' => 'ephemeral_ticket_v1',
        ]);
        $steps['login'] = $this->requestStep($target, '/login', 'login', [
            'card_key' => $target['cardKey'],
            'challenge_id' => 'ephemeral.' . $this->randomAlpha(28),
            'install_id' => $target['installId'],
            'device_name' => 'Parity Device',
            'machine_profile_hash' => $target['machineProfileHash'],
            'timestamp' => time(),
            'signature' => '',
            'device_key_mode' => 'ephemeral_ticket_v1',
            'client_version' => '1.0.0',
        ]);
        $this->applyRotation($steps['login'], $state);
        $steps['heartbeat'] = $this->sessionStep($target, $state, '/heartbeat', []);
        $steps['config'] = $this->sessionStep($target, $state, '/config', []);
        $steps['variable'] = $this->sessionStep($target, $state, '/variable', [
            'name' => $target['variableName'],
        ]);
        $steps['cloudTicket'] = $this->sessionStep($target, $state, '/cloud/download-ticket', [
            'file_key' => $target['fileKey'],
        ]);
        $steps['cloudDownload'] = $this->downloadStep($target, $steps['cloudTicket']);
        $eventPayload = $this->securityPayload('evt.' . strtolower($target['name']) . '.' . $this->randomAlpha(18));
        $steps['securityReport'] = $this->sessionStep($target, $state, '/security/report', $eventPayload);
        $steps['securityDuplicate'] = $this->sessionStep($target, $state, '/security/report', $eventPayload);
        $steps['logout'] = $this->sessionStep($target, $state, '/logout', []);
        $steps['postLogoutHeartbeat'] = $this->requestStep(
            $target,
            '/heartbeat',
            self::SESSION_ROUTES['/heartbeat'],
            $this->sessionPayload($target, $state, [])
        );
        return [
            'name' => $target['name'],
            'steps' => $steps,
            'facts' => $this->targetFacts($steps),
        ];
    }

    private function runActionTarget(array $target, string $requestedAction): array
    {
        $state = ['counter' => 1, 'token' => '', 'sessionTicket' => ''];
        $steps = [];
        $steps['login'] = $this->requestStep($target, '/login', 'login', [
            'card_key' => $target['cardKey'],
            'challenge_id' => 'ephemeral.' . $this->randomAlpha(28),
            'install_id' => $target['installId'],
            'device_name' => 'Parity Device',
            'machine_profile_hash' => $target['machineProfileHash'],
            'timestamp' => time(),
            'signature' => '',
            'device_key_mode' => 'ephemeral_ticket_v1',
            'client_version' => '1.0.0',
        ]);
        $this->applyRotation($steps['login'], $state);
        $eventPayload = $this->securityPayload(
            'evt.' . strtolower($target['name']) . '.' . $this->randomAlpha(18),
            $requestedAction,
            'critical',
            100
        );
        $steps['securityAction'] = $this->requestStep(
            $target,
            '/security/report',
            self::SESSION_ROUTES['/security/report'],
            $this->sessionPayload($target, $state, $eventPayload)
        );
        $state['counter']++;
        $steps['duplicateAfterAction'] = $this->requestStep(
            $target,
            '/security/report',
            self::SESSION_ROUTES['/security/report'],
            $this->sessionPayload($target, $state, $eventPayload)
        );
        $state['counter']++;
        $steps['postActionHeartbeat'] = $this->requestStep(
            $target,
            '/heartbeat',
            self::SESSION_ROUTES['/heartbeat'],
            $this->sessionPayload($target, $state, [])
        );
        return [
            'name' => $target['name'],
            'steps' => $steps,
            'facts' => $this->actionTargetFacts($steps, $requestedAction),
        ];
    }

    private function sessionStep(array $target, array &$state, string $route, array $extraPayload): array
    {
        $step = $this->requestStep(
            $target,
            $route,
            self::SESSION_ROUTES[$route],
            $this->sessionPayload($target, $state, $extraPayload)
        );
        if ($route !== '/logout') {
            $this->applyRotation($step, $state);
        }
        $state['counter']++;
        return $step;
    }

    private function requestStep(array $target, string $route, string $callId, array $payload): array
    {
        $response = $this->httpJson(
            $target['baseUrl'] . '/api/v1/index.php?route=' . rawurlencode($route),
            [
                'Content-Type' => 'application/json',
                'X-App-Code' => $target['appCode'],
                'X-Api-Token' => $target['apiToken'],
                'X-Api-Call-Id' => $callId,
                'X-Plain-Client' => '1',
            ],
            $payload
        );
        return [
            'route' => $route,
            'httpStatus' => $response['httpStatus'],
            'body' => $response['body'],
        ];
    }

    private function downloadStep(array $target, array $ticketStep): array
    {
        $data = $this->successData($ticketStep);
        $downloadUrl = (string)($data['download_url'] ?? '');
        $response = $this->httpGet($target['baseUrl'] . $downloadUrl);
        return [
            'route' => '/cloud/download',
            'httpStatus' => $response['httpStatus'],
            'contentType' => $response['headers']['content-type'] ?? '',
            'contentDisposition' => $response['headers']['content-disposition'] ?? '',
            'contentLength' => $response['headers']['content-length'] ?? '',
            'sha256' => hash('sha256', $response['content']),
            'expectedSha256' => $target['fileSha256'],
        ];
    }

    private function sessionPayload(array $target, array $state, array $extraPayload): array
    {
        return $extraPayload + [
            'token' => $state['token'],
            'install_id' => $target['installId'],
            'counter' => $state['counter'],
            'timestamp' => time(),
            'request_nonce' => 'nonce' . $this->randomAlpha(24),
            'session_ticket' => $state['sessionTicket'],
            'signature' => '',
        ];
    }

    private function securityPayload(
        string $eventId,
        string $requestedAction = 'record_only',
        string $riskLevel = 'low',
        int $confidence = 10
    ): array
    {
        $actionReason = $requestedAction === 'record_only' ? '' : 'parity-action-' . $requestedAction;
        return [
            'event_id' => $eventId,
            'event_type' => 'debugger_detected',
            'risk_level' => $riskLevel,
            'confidence' => $confidence,
            'requested_action' => $requestedAction,
            'action_reason' => $actionReason,
            'title' => 'Parity security report',
            'message' => 'Client parity security report',
            'evidence' => ['detector' => 'parity'],
            'attestation' => ['provider' => 'parity', 'verdict' => 'ok'],
            'occurred_at' => time(),
            'sdk_version' => '1.0.0',
            'detector_version' => '1.0.0',
            'platform' => 'windows',
        ];
    }

    private function applyRotation(array $step, array &$state): void
    {
        $data = $this->successData($step);
        $token = (string)($data['token'] ?? '');
        $ticket = (string)($data['session_ticket'] ?? '');
        if ($token === '' || $ticket === '') {
            throw new RuntimeException($step['route'] . ' did not return rotated session fields');
        }
        $state['token'] = $token;
        $state['sessionTicket'] = $ticket;
    }

    private function targetFacts(array $steps): array
    {
        return [
            'notice' => $this->successData($steps['notice'])['notice'] ?? null,
            'loginChallengeOk' => $this->hasDataKeys($steps['loginChallenge'], ['challenge_id', 'server_nonce', 'expires_at']),
            'login' => $this->sessionFacts($steps['login']) + [
                'ipCheck' => $this->successData($steps['login'])['ip_check'] ?? null,
            ],
            'heartbeat' => $this->sessionFacts($steps['heartbeat']) + [
                'ok' => $this->successData($steps['heartbeat'])['ok'] ?? null,
            ],
            'config' => $this->sessionFacts($steps['config']) + [
                'version' => $this->successData($steps['config'])['version'] ?? null,
                'downloadUrl' => $this->successData($steps['config'])['download_url'] ?? null,
                'forceUpdate' => $this->successData($steps['config'])['force_update'] ?? null,
                'notice' => $this->successData($steps['config'])['notice'] ?? null,
            ],
            'variable' => $this->sessionFacts($steps['variable']) + [
                'value' => $this->successData($steps['variable'])['value'] ?? null,
            ],
            'cloudTicket' => $this->sessionFacts($steps['cloudTicket']) + [
                'hasTicket' => $this->hasDataKeys($steps['cloudTicket'], ['download_ticket', 'download_url', 'expires_at']),
            ],
            'cloudDownload' => [
                'httpStatus' => $steps['cloudDownload']['httpStatus'],
                'contentType' => $steps['cloudDownload']['contentType'],
                'contentDisposition' => $steps['cloudDownload']['contentDisposition'],
                'contentLength' => $steps['cloudDownload']['contentLength'],
                'contentMatches' => $steps['cloudDownload']['sha256'] === $steps['cloudDownload']['expectedSha256'],
            ],
            'securityReport' => $this->securityFacts($steps['securityReport'], false),
            'securityDuplicate' => $this->securityFacts($steps['securityDuplicate'], true),
            'logout' => [
                'httpStatus' => $steps['logout']['httpStatus'],
                'loggedOut' => $this->successData($steps['logout'])['logged_out'] ?? null,
            ],
            'postLogoutHeartbeat' => [
                'httpStatus' => $steps['postLogoutHeartbeat']['httpStatus'],
                'error' => $steps['postLogoutHeartbeat']['body']['error'] ?? '',
            ],
        ];
    }

    private function actionTargetFacts(array $steps, string $requestedAction): array
    {
        return [
            'login' => $this->sessionFacts($steps['login']),
            'securityAction' => $this->securityActionFacts($steps['securityAction'], $requestedAction),
            'duplicateAfterAction' => $this->errorFacts($steps['duplicateAfterAction']),
            'postActionHeartbeat' => $this->errorFacts($steps['postActionHeartbeat']),
        ];
    }

    private function sessionFacts(array $step): array
    {
        $data = $this->successData($step);
        return [
            'httpStatus' => $step['httpStatus'],
            'proofMode' => $data['proof_mode'] ?? null,
            'heartbeatInterval' => $data['heartbeat_interval'] ?? null,
            'hasToken' => !empty($data['token']),
            'hasTicket' => !empty($data['session_ticket']),
            'hasTokenExpiry' => !empty($data['token_expires_at']),
            'hasTicketExpiry' => !empty($data['ticket_expires_at']),
            'hasCardExpiry' => !empty($data['card_expires_at']),
        ];
    }

    private function securityFacts(array $step, bool $duplicate): array
    {
        $data = $this->successData($step);
        return $this->sessionFacts($step) + [
            'messageIdPresent' => (int)($data['message_id'] ?? 0) > 0,
            'reportIdPresent' => (int)($data['report_id'] ?? 0) > 0,
            'riskScore' => $data['risk_score'] ?? null,
            'requestedAction' => $data['requested_action'] ?? null,
            'action' => $data['action'] ?? null,
            'actionSource' => $data['action_source'] ?? null,
            'sessionRevoked' => $data['session_revoked'] ?? null,
            'deviceDisabled' => $data['device_disabled'] ?? null,
            'cardDisabled' => $data['card_disabled'] ?? null,
            'revokedSessions' => $data['revoked_sessions'] ?? null,
            'duplicate' => $duplicate ? ($data['duplicate'] ?? null) : !array_key_exists('duplicate', $data),
        ];
    }

    private function securityActionFacts(array $step, string $requestedAction): array
    {
        $data = $this->successData($step);
        return [
            'httpStatus' => $step['httpStatus'],
            'messageIdPresent' => (int)($data['message_id'] ?? 0) > 0,
            'reportIdPresent' => (int)($data['report_id'] ?? 0) > 0,
            'riskScore' => $data['risk_score'] ?? null,
            'requestedAction' => $data['requested_action'] ?? null,
            'action' => $data['action'] ?? null,
            'expectedActionMatched' => ($data['action'] ?? null) === $requestedAction,
            'actionSource' => $data['action_source'] ?? null,
            'sessionRevoked' => $data['session_revoked'] ?? null,
            'deviceDisabled' => $data['device_disabled'] ?? null,
            'cardDisabled' => $data['card_disabled'] ?? null,
            'revokedSessions' => $data['revoked_sessions'] ?? null,
            'revokedSessionsPositive' => (int)($data['revoked_sessions'] ?? 0) > 0,
            'hasRotatedToken' => array_key_exists('token', $data),
            'hasRotatedTicket' => array_key_exists('session_ticket', $data),
        ];
    }

    private function errorFacts(array $step): array
    {
        return [
            'httpStatus' => $step['httpStatus'],
            'code' => $step['body']['code'] ?? null,
            'error' => $step['body']['error'] ?? '',
        ];
    }

    private function successData(array $step): array
    {
        $body = $step['body'] ?? [];
        if (($step['httpStatus'] ?? 0) !== 200 || ($body['code'] ?? null) !== 0 || !is_array($body['data'] ?? null)) {
            $error = $body['error'] ?? $body['message'] ?? 'invalid response';
            throw new RuntimeException($step['route'] . ' failed: ' . (string)$error);
        }
        return $body['data'];
    }

    private function hasDataKeys(array $step, array $keys): bool
    {
        $data = $this->successData($step);
        foreach ($keys as $key) {
            if (!array_key_exists($key, $data) || $data[$key] === '' || $data[$key] === null) {
                return false;
            }
        }
        return true;
    }

    private function compareResults(array $phpResult, array $rustResult, string $prefix): array
    {
        $diffs = [];
        $this->compareValues($prefix, $phpResult['facts'], $rustResult['facts'], $diffs);
        return $diffs;
    }

    private function actionExpectationDiffs(string $targetName, string $action, array $result): array
    {
        $facts = $result['facts']['securityAction'];
        $expected = [
            'expectedActionMatched' => true,
            'sessionRevoked' => true,
            'revokedSessionsPositive' => true,
            'hasRotatedToken' => false,
            'hasRotatedTicket' => false,
            'actionSource' => 'client',
            'deviceDisabled' => $action === 'disable_device',
            'cardDisabled' => $action === 'disable_card',
        ];
        $diffs = [];
        foreach ($expected as $key => $value) {
            if (($facts[$key] ?? null) !== $value) {
                $diffs[] = 'expect.' . $targetName . '.securityActions.' . $action . '.' . $key
                    . ' expected=' . json_encode($value, JSON_UNESCAPED_SLASHES)
                    . ' actual=' . json_encode($facts[$key] ?? null, JSON_UNESCAPED_SLASHES);
            }
        }
        foreach (['duplicateAfterAction', 'postActionHeartbeat'] as $stepName) {
            $errorFacts = $result['facts'][$stepName];
            if (($errorFacts['httpStatus'] ?? null) !== 401 || ($errorFacts['error'] ?? '') !== 'SESSION_INVALID') {
                $diffs[] = 'expect.' . $targetName . '.securityActions.' . $action . '.' . $stepName
                    . ' expected=SESSION_INVALID actual=' . json_encode($errorFacts, JSON_UNESCAPED_SLASHES);
            }
        }
        return $diffs;
    }

    private function compareValues(string $path, mixed $left, mixed $right, array &$diffs): void
    {
        if (is_array($left) && is_array($right)) {
            foreach (array_unique(array_merge(array_keys($left), array_keys($right))) as $key) {
                $this->compareValues($path === '' ? (string)$key : $path . '.' . $key, $left[$key] ?? null, $right[$key] ?? null, $diffs);
            }
            return;
        }
        if ($left !== $right) {
            $diffs[] = $path . ' php=' . json_encode($left, JSON_UNESCAPED_SLASHES) . ' rust=' . json_encode($right, JSON_UNESCAPED_SLASHES);
        }
    }

    private function printTargetResult(array $result): void
    {
        echo strtoupper($result['name']) . " client session parity steps\n";
        foreach ($result['steps'] as $name => $step) {
            $body = $step['body'] ?? [];
            $code = $body['code'] ?? '';
            $error = $body['error'] ?? '';
            $status = $step['httpStatus'] ?? 0;
            echo "{$name} http={$status} code={$code}";
            if ($error !== '') {
                echo " error={$error}";
            }
            echo "\n";
        }
    }

    private function httpJson(string $url, array $headers, array $payload): array
    {
        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }
        $content = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!is_string($content)) {
            throw new RuntimeException('request payload encode failed');
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
        $status = $this->httpStatus($http_response_header ?? []);
        $body = json_decode(is_string($raw) ? $raw : '', true);
        return [
            'httpStatus' => $status,
            'body' => is_array($body) ? $body : ['error' => 'NON_JSON_RESPONSE'],
        ];
    }

    private function httpGet(string $url): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'ignore_errors' => true,
                'timeout' => 10,
            ],
        ]);
        $content = @file_get_contents($url, false, $context);
        $responseHeaders = $http_response_header ?? [];
        return [
            'httpStatus' => $this->httpStatus($responseHeaders),
            'headers' => $this->headersByName($responseHeaders),
            'content' => is_string($content) ? $content : '',
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

    private function headersByName(array $headers): array
    {
        $result = [];
        foreach ($headers as $header) {
            $parts = explode(':', (string)$header, 2);
            if (count($parts) === 2) {
                $result[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
        }
        return $result;
    }

    private function insertApp(string $appCode, string $apiToken): void
    {
        $this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appCode, $apiToken, 'Parity Client App', 1, 50, 300, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, $this->json(ClientApiConfig::defaults()), '1.0.0', 'local_key_v1', 'rsa_oaep_aes_256_gcm', '', '', 'client parity check']
        );
    }

    private function insertCard(int $appId, string $appCode, string $cardKey): void
    {
        $cardId = $this->exec(
            'INSERT INTO `auth_cards` (`app_id`, `card_hash`, `card_cipher`, `card_fingerprint`, `card_type`, `duration_seconds`, `total_uses`, `remaining_uses`, `max_devices`, `card_structure`, `prefix`, `unbind_limit`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, hash('sha256', $appCode . ':' . $cardKey), Crypto::encryptProtectedText($cardKey, $this->systemKey), CardKeyFactory::fingerprint($cardKey), 'time', 86400, 0, 0, 50, 'custom', 'E2E', 0, 0]
        );
        $this->replaceCardSearchTokens($appId, (int)$cardId, $cardKey);
    }

    private function replaceCardSearchTokens(int $appId, int $cardId, string $cardKey): void
    {
        if (!$this->tableExists('auth_card_search_tokens')) {
            return;
        }
        $this->exec('DELETE FROM `auth_card_search_tokens` WHERE `app_id` = ? AND `card_id` = ?', [$appId, $cardId]);
        foreach (array_chunk(CardSearchIndex::cardTokenHashes($cardKey, $this->systemKey), 200) as $hashes) {
            $values = [];
            $params = [];
            foreach ($hashes as $hash) {
                $values[] = '(DEFAULT, ?, ?, ?)';
                array_push($params, $appId, $cardId, $hash);
            }
            if ($values !== []) {
                $this->exec('INSERT IGNORE INTO `auth_card_search_tokens` (`id`, `app_id`, `card_id`, `token_hash`) VALUES ' . implode(', ', $values), $params);
            }
        }
    }

    private function insertRemoteConfig(int $appId): void
    {
        $this->exec(
            'INSERT INTO `auth_remote_configs` (`app_id`, `notice`, `config_json`, `variables_json`, `version`, `force_update`, `download_url`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [$appId, 'Parity notice', '{"mode":"parity"}', '{"flag":"on"}', '1.0.0', 0, 'https://example.invalid/download', 1]
        );
    }

    private function insertRemoteVariable(string $name, string $value): void
    {
        $this->exec(
            'INSERT INTO `auth_remote_variables` (`name`, `value`, `scope`, `status`) VALUES (?, ?, ?, ?)',
            [$name, $value, 'public', 1]
        );
    }

    private function insertCloudFile(string $fileKey, string $objectKey, int $localConfigId, string $content): void
    {
        $this->objectKeys[] = $objectKey;
        $this->exec(
            'INSERT INTO `auth_cloud_files` (`file_key`, `provider`, `config_id`, `original_name`, `mime_type`, `extension`, `size_bytes`, `sha256`, `object_key`, `local_path`, `status`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [$fileKey, 'local', $localConfigId, 'parity.txt', 'text/plain', 'txt', strlen($content), hash('sha256', $content), $objectKey, $objectKey, 'active', 'client parity check']
        );
    }

    private function ensureLocalStorageConfig(): int
    {
        $row = $this->database->selectRowV2('SELECT `id` FROM `auth_cloud_storage_configs` WHERE `provider` = ?', ['local']);
        if (is_array($row) && isset($row['id'])) {
            return (int)$row['id'];
        }
        $configId = (int)$this->exec(
            'INSERT INTO `auth_cloud_storage_configs` (`provider`, `status`, `is_default`, `bucket`, `region`, `endpoint`, `access_key`, `secret_cipher`, `path_prefix`, `custom_domain`, `max_file_size`, `allowed_extensions`, `signed_url_ttl_seconds`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            ['local', 1, 0, '', '', '', '', null, '', '', 104857600, '', 300]
        );
        $this->createdLocalConfigIds[] = $configId;
        return $configId;
    }

    private function writeLocalObject(string $objectKey, string $content): void
    {
        foreach ([$this->phpProjectRoot, $this->rustProjectRoot] as $root) {
            $path = $root . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'cloud-storage' . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $objectKey);
            $directory = dirname($path);
            if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) {
                throw new RuntimeException('local object directory create failed');
            }
            if (file_put_contents($path, $content) !== strlen($content)) {
                throw new RuntimeException('local object write failed');
            }
        }
    }

    private function cleanup(): void
    {
        $appIds = array_map(
            static fn(array $row): int => (int)$row['id'],
            $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::APP_PREFIX . '%'])
        );
        foreach ($appIds as $appId) {
            $this->deleteAppRows($appId);
        }
        $this->deleteRemoteVariables();
        $this->deleteCloudFiles();
        foreach ($this->createdLocalConfigIds as $configId) {
            $this->exec('DELETE FROM `auth_cloud_storage_configs` WHERE `id` = ? AND `provider` = ?', [$configId, 'local']);
        }
        $this->deleteLocalObjects();
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

    private function deleteRemoteVariables(): void
    {
        $rows = $this->database->selectV2('SELECT `id` FROM `auth_remote_variables` WHERE `name` LIKE ?', [self::VARIABLE_PREFIX . '%']);
        foreach ($rows as $row) {
            $variableId = (int)$row['id'];
            if ($this->tableExists('auth_remote_variable_apps')) {
                $this->exec('DELETE FROM `auth_remote_variable_apps` WHERE `variable_id` = ?', [$variableId]);
            }
            $this->exec('DELETE FROM `auth_remote_variables` WHERE `id` = ?', [$variableId]);
        }
    }

    private function deleteCloudFiles(): void
    {
        $rows = $this->database->selectV2('SELECT `object_key` FROM `auth_cloud_files` WHERE `file_key` LIKE ?', [self::FILE_PREFIX . '%']);
        foreach ($rows as $row) {
            $this->objectKeys[] = (string)$row['object_key'];
        }
        $this->exec('DELETE FROM `auth_cloud_files` WHERE `file_key` LIKE ?', [self::FILE_PREFIX . '%']);
    }

    private function deleteLocalObjects(): void
    {
        foreach (array_unique($this->objectKeys) as $objectKey) {
            foreach ([$this->phpProjectRoot, $this->rustProjectRoot] as $root) {
                $path = $root . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'cloud-storage' . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $objectKey);
                if (is_file($path)) {
                    unlink($path);
                }
            }
        }
    }

    private function insertedId(string $table, string $column, string $value): int
    {
        $row = $this->database->selectRowV2("SELECT `id` FROM `{$table}` WHERE `{$column}` = ?", [$value]);
        if (!is_array($row) || !isset($row['id'])) {
            throw new RuntimeException("inserted row missing for {$table}");
        }
        return (int)$row['id'];
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

    private function json(array $value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
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

$check = new ClientSessionParityCheck(
    $DB,
    (string)SYS_KEY,
    $phpProjectRoot,
    $rustProjectRoot,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
