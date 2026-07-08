<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class AdminMessagesParityCheck
{
    private const PREFIX = 'E2E_ADMIN_MSG_';

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
            $phpResult = $this->runTarget($this->createTarget('php', $this->phpBaseUrl), $session);
            $rustResult = $this->runTarget($this->createTarget('rust', $this->rustBaseUrl), $session);
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'adminMessages');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            echo "PARITY_OK admin messages\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $suffix = strtoupper(substr($name, 0, 3)) . '_' . strtoupper($this->randomAlpha(6));
        $appCode = self::PREFIX . 'APP_' . $suffix;
        $appId = $this->insertApp($appCode);
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => $appCode,
            'appId' => $appId,
            'labelPrefix' => self::PREFIX . $suffix . '_',
        ];
    }

    private function runTarget(array $target, array $session): array
    {
        $fixtures = $this->seedMessages($target);
        $steps = [];
        $steps['listAll'] = $this->normalizeMessageList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/list',
            ['app_code' => $target['appCode'], 'page' => 1, 'limit' => 50]
        )), $target);
        $steps['filterStatus'] = $this->normalizeMessageList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/list',
            ['app_code' => $target['appCode'], 'status' => 'unread', 'page' => 1, 'limit' => 50]
        )), $target);
        $steps['filterActionRiskEvent'] = $this->normalizeMessageList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/list',
            [
                'app_code' => $target['appCode'],
                'action' => 'manual_review',
                'risk_level' => 'high',
                'event_type' => 'debugger_detected',
                'page' => 1,
                'limit' => 50,
            ]
        )), $target);
        $steps['filterCardInstallIpDate'] = $this->normalizeMessageList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/list',
            [
                'app_code' => $target['appCode'],
                'card_fingerprint' => $fixtures['detail']['card_fingerprint'],
                'install_id' => $fixtures['detail']['install_id'],
                'ip' => '127.0.0.1',
                'start' => '2024-01-01',
                'end' => '2024-12-31',
                'page' => 1,
                'limit' => 50,
            ]
        )), $target);
        $steps['detail'] = $this->normalizeDetail($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/detail',
            ['app_code' => $target['appCode'], 'message_id' => $fixtures['detail']['message_id']]
        )), $target);

        $steps['read'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/read',
            ['app_code' => $target['appCode'], 'message_ids' => [$fixtures['read']['message_id']], 'remark' => 'read remark']
        ));
        $steps['readFact'] = $this->messageFact($fixtures['read']['message_id']);
        $steps['handling'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/handling',
            ['app_code' => $target['appCode'], 'message_ids' => [$fixtures['handling']['message_id']], 'remark' => 'handling remark']
        ));
        $steps['handlingFact'] = $this->messageFact($fixtures['handling']['message_id']);
        $steps['handle'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/handle',
            ['app_code' => $target['appCode'], 'message_ids' => [$fixtures['handle']['message_id']], 'remark' => 'handle remark']
        ));
        $steps['handleFact'] = $this->messageFact($fixtures['handle']['message_id']);
        $steps['archive'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/archive',
            ['app_code' => $target['appCode'], 'message_ids' => [$fixtures['archive']['message_id']], 'remark' => 'archive remark']
        ));
        $steps['archiveFact'] = $this->messageFact($fixtures['archive']['message_id']);

        $steps['manualAction'] = $this->normalizeActionEffect($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/action',
            [
                'app_code' => $target['appCode'],
                'message_id' => $fixtures['manual']['message_id'],
                'action' => 'manual_review',
                'remark' => 'manual action remark',
            ]
        )));
        $steps['manualFact'] = $this->messageFact($fixtures['manual']['message_id']);
        $steps['kickAction'] = $this->normalizeActionEffect($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/action',
            [
                'app_code' => $target['appCode'],
                'message_id' => $fixtures['kick']['message_id'],
                'action' => 'kick_session',
                'remark' => 'kick remark',
            ]
        )));
        $steps['kickFact'] = $this->messageTargetFact($fixtures['kick']);
        $steps['deviceAction'] = $this->normalizeActionEffect($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/action',
            [
                'app_code' => $target['appCode'],
                'message_id' => $fixtures['device']['message_id'],
                'action' => 'disable_device',
                'remark' => 'device remark',
            ]
        )));
        $steps['deviceFact'] = $this->messageTargetFact($fixtures['device']);
        $steps['cardAction'] = $this->normalizeActionEffect($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/action',
            [
                'app_code' => $target['appCode'],
                'message_id' => $fixtures['card']['message_id'],
                'action' => 'disable_card',
                'remark' => 'card remark',
            ]
        )));
        $steps['cardFact'] = $this->messageTargetFact($fixtures['card']);

        $steps['invalidStatus'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/messages/list',
            ['app_code' => $target['appCode'], 'status' => 'new']
        ));
        $steps['invalidAction'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/messages/action',
            ['app_code' => $target['appCode'], 'message_id' => $fixtures['manual']['message_id'], 'action' => 'wipe_disk']
        ));
        $steps['missingDetail'] = $this->normalizeError($this->adminRequest(
            $target,
            $session,
            '/admin/messages/detail',
            ['app_code' => $target['appCode'], 'message_id' => 999999999]
        ));

        $steps['delete'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/messages/delete',
            ['app_code' => $target['appCode'], 'message_ids' => [$fixtures['delete']['message_id']]]
        ));
        $steps['deleteFact'] = [
            'message_exists' => $this->rowExists('auth_messages', (int)$fixtures['delete']['message_id']),
            'actions' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_message_actions` WHERE `message_id` = ?', [$fixtures['delete']['message_id']]),
        ];

        return ['steps' => $steps];
    }

    private function seedMessages(array $target): array
    {
        $labels = ['detail', 'read', 'handling', 'handle', 'archive', 'manual', 'kick', 'device', 'card', 'delete'];
        $fixtures = [];
        foreach ($labels as $index => $label) {
            $fixtures[$label] = $this->seedMessage($target, $label, $index + 1);
        }
        return $fixtures;
    }

    private function seedMessage(array $target, string $label, int $index): array
    {
        $appId = (int)$target['appId'];
        $cardCode = $target['labelPrefix'] . 'CARD_' . strtoupper($label);
        $cardHash = hash('sha256', $cardCode);
        $cardFingerprint = strtoupper(substr($label, 0, 4)) . substr(hash('sha256', $cardCode), 0, 8);
        $cardId = (int)$this->exec(
            'INSERT INTO `auth_cards` (`app_id`, `card_hash`, `card_cipher`, `card_fingerprint`, `card_type`, `duration_seconds`, `total_uses`, `remaining_uses`, `max_devices`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                $cardHash,
                Crypto::encryptSecret($cardCode, $this->systemKey),
                $cardFingerprint,
                'time',
                3600,
                0,
                0,
                50,
                1,
            ]
        );
        $installId = 'INSTALL_' . strtoupper(substr(hash('sha256', $target['appCode'] . ':' . $label), 0, 24));
        $deviceId = (int)$this->exec(
            'INSERT INTO `auth_devices` (`app_id`, `account_id`, `card_id`, `card_hash`, `device_hash`, `device_name`, `install_id`, `device_public_key`, `device_key_alg`, `machine_profile_hash`, `bind_ip`, `bind_region`, `risk_level`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                null,
                $cardId,
                $cardHash,
                hash('sha256', $target['appCode'] . ':device:' . $label),
                'Parity Message Device ' . $label,
                $installId,
                '',
                'local_key_v1',
                hash('sha256', $target['appCode'] . ':machine:' . $label),
                '127.0.0.1',
                'Local',
                0,
                1,
            ]
        );
        $sessionId = (int)$this->exec(
            'INSERT INTO `auth_sessions` (`app_id`, `account_id`, `device_id`, `card_id`, `card_hash`, `card_fingerprint`, `token_hash`, `request_counter`, `proof_mode`, `ticket_hash`, `ticket_expires_at`, `status`, `ip`, `expires_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                null,
                $deviceId,
                $cardId,
                $cardHash,
                $cardFingerprint,
                hash('sha256', $target['appCode'] . ':session:' . $label),
                1,
                'local_key_v1',
                null,
                null,
                1,
                '127.0.0.1',
                date('Y-m-d H:i:s', time() + 3600),
            ]
        );
        $risk = $label === 'archive' ? 'low' : 'high';
        $action = match ($label) {
            'kick' => 'kick_session',
            'device' => 'disable_device',
            'card' => 'disable_card',
            default => 'manual_review',
        };
        $eventType = $label === 'archive' ? 'root_detected' : 'debugger_detected';
        $createdAt = sprintf('2024-01-%02d 10:00:00', min(28, $index));
        $reportId = (int)$this->exec(
            'INSERT INTO `auth_security_reports` (`app_id`, `session_id`, `device_id`, `card_id`, `card_hash`, `card_fingerprint`, `install_id`, `event_id`, `event_type`, `risk_level`, `confidence`, `requested_action`, `action`, `action_source`, `risk_score`, `action_reason`, `title`, `message`, `evidence_json`, `attestation_json`, `sdk_version`, `detector_version`, `platform`, `ip`, `occurred_at`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                $sessionId,
                $deviceId,
                $cardId,
                $cardHash,
                $cardFingerprint,
                $installId,
                $target['labelPrefix'] . 'EVENT_' . strtoupper($label),
                $eventType,
                $risk,
                70 + $index,
                $action,
                $action,
                'client',
                70 + $index,
                'reason ' . $label,
                $target['labelPrefix'] . 'REPORT_' . strtoupper($label),
                'report message ' . $label,
                '{"probe":"message","label":"' . $label . '"}',
                '{"attested":true}',
                'sdk-' . $label,
                'detector-' . $label,
                'windows',
                '127.0.0.1',
                $createdAt,
                $createdAt,
            ]
        );
        $status = $label === 'archive' ? 'archived' : 'unread';
        $messageId = (int)$this->exec(
            'INSERT INTO `auth_messages` (`app_id`, `report_id`, `session_id`, `device_id`, `card_id`, `message_type`, `severity`, `status`, `title`, `summary`, `action`, `action_source`, `risk_score`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                $reportId,
                $sessionId,
                $deviceId,
                $cardId,
                'security_report',
                $risk,
                $status,
                $target['labelPrefix'] . 'MESSAGE_' . strtoupper($label),
                'summary ' . $label,
                $action,
                'client',
                70 + $index,
                $createdAt,
            ]
        );
        if ($label === 'detail' || $label === 'delete') {
            $this->exec(
                'INSERT INTO `auth_message_actions` (`app_id`, `message_id`, `action`, `actor_type`, `actor_name`, `result`, `remark`, `ip`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [$appId, $messageId, 'manual_review', 'admin', self::PREFIX . 'seed_actor', 'success', 'seed remark', '127.0.0.1', $createdAt]
            );
            $this->exec(
                'INSERT INTO `auth_audit_logs` (`app_id`, `account_id`, `action`, `message`, `ip`, `region`, `created_at`) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [$appId, null, 'message_seed', '消息#' . $messageId . ' seed audit', '127.0.0.1', 'Local', $createdAt]
            );
        }
        return [
            'message_id' => $messageId,
            'session_id' => $sessionId,
            'device_id' => $deviceId,
            'card_id' => $cardId,
            'card_fingerprint' => $cardFingerprint,
            'install_id' => $installId,
        ];
    }

    private function normalizeMessageList(array $data, array $target): array
    {
        $rows = [];
        foreach (is_array($data['messages'] ?? null) ? $data['messages'] : [] as $row) {
            $rows[] = $this->normalizeMessage($row, $target);
        }
        usort($rows, static fn(array $left, array $right): int => strcmp($left['title'], $right['title']));
        return $rows;
    }

    private function normalizeDetail(array $data, array $target): array
    {
        $message = is_array($data['message'] ?? null) ? $data['message'] : [];
        $normalized = $this->normalizeMessage($message, $target);
        $normalized['message_id'] = $this->dynamicId($message['message_id'] ?? null);
        $normalized['report_id'] = $this->dynamicId($message['report_id'] ?? null);
        $normalized['session_id'] = $this->dynamicId($message['session_id'] ?? null);
        $normalized['device_id'] = $this->dynamicId($message['device_id'] ?? null);
        $normalized['card_id'] = $this->dynamicId($message['card_id'] ?? null);
        $normalized['action_reason'] = (string)($message['action_reason'] ?? '');
        $normalized['message'] = (string)($message['message'] ?? '');
        $normalized['evidence_keys'] = $this->sortedKeys(is_array($message['evidence'] ?? null) ? $message['evidence'] : []);
        $normalized['attestation_keys'] = $this->sortedKeys(is_array($message['attestation'] ?? null) ? $message['attestation'] : []);
        $normalized['sdk_version_state'] = trim((string)($message['sdk_version'] ?? '')) === '' ? 'empty' : 'present';
        $normalized['detector_version_state'] = trim((string)($message['detector_version'] ?? '')) === '' ? 'empty' : 'present';
        $normalized['read_at_state'] = $this->dateState($message['read_at'] ?? '');
        $normalized['handled_by_state'] = trim((string)($message['handled_by'] ?? '')) === '' ? 'empty' : 'present';
        $normalized['handled_at_state'] = $this->dateState($message['handled_at'] ?? '');
        $normalized['archived_at_state'] = $this->dateState($message['archived_at'] ?? '');
        $normalized['actions'] = $this->normalizeActions(is_array($message['actions'] ?? null) ? $message['actions'] : []);
        $normalized['audits'] = $this->normalizeAudits(is_array($message['audits'] ?? null) ? $message['audits'] : []);
        return $normalized;
    }

    private function normalizeMessage(mixed $row, array $target): array
    {
        $row = is_array($row) ? $row : [];
        return [
            'keys' => $this->sortedKeys($row),
            'id' => $this->dynamicId($row['id'] ?? null),
            'event_id' => $this->normalizeTargetText((string)($row['event_id'] ?? ''), $target),
            'event_type' => (string)($row['event_type'] ?? ''),
            'risk_level' => (string)($row['risk_level'] ?? ''),
            'confidence' => (int)($row['confidence'] ?? -1),
            'requested_action' => (string)($row['requested_action'] ?? ''),
            'action' => (string)($row['action'] ?? ''),
            'action_source' => (string)($row['action_source'] ?? ''),
            'status' => (string)($row['status'] ?? ''),
            'title' => $this->normalizeTargetText((string)($row['title'] ?? ''), $target),
            'summary' => (string)($row['summary'] ?? ''),
            'risk_score' => (int)($row['risk_score'] ?? -1),
            'card_fingerprint_state' => trim((string)($row['card_fingerprint'] ?? '')) === '' ? 'empty' : 'present',
            'install_id_state' => trim((string)($row['install_id'] ?? '')) === '' ? 'empty' : 'present',
            'ip' => $this->normalizeIp((string)($row['ip'] ?? '')),
            'platform' => (string)($row['platform'] ?? ''),
            'occurred_at_state' => $this->dateState($row['occurred_at'] ?? ''),
            'created_at_state' => $this->dateState($row['created_at'] ?? ''),
        ];
    }

    private function normalizeActions(array $actions): array
    {
        $rows = [];
        foreach ($actions as $action) {
            $action = is_array($action) ? $action : [];
            $rows[] = [
                'id' => $this->dynamicId($action['id'] ?? null),
                'action' => (string)($action['action'] ?? ''),
                'actor_type' => (string)($action['actor_type'] ?? ''),
                'actor_name_state' => str_starts_with((string)($action['actor_name'] ?? ''), self::PREFIX) ? 'parity' : 'other',
                'result' => (string)($action['result'] ?? ''),
                'remark_state' => trim((string)($action['remark'] ?? '')) === '' ? 'empty' : 'present',
                'ip' => $this->normalizeIp((string)($action['ip'] ?? '')),
                'created_at_state' => $this->dateState($action['created_at'] ?? ''),
            ];
        }
        return $rows;
    }

    private function normalizeAudits(array $audits): array
    {
        $rows = [];
        foreach ($audits as $audit) {
            $audit = is_array($audit) ? $audit : [];
            $rows[] = [
                'id' => $this->dynamicId($audit['id'] ?? null),
                'action' => (string)($audit['action'] ?? ''),
                'message' => preg_replace('/消息#\d+/', '消息#<id>', (string)($audit['message'] ?? '')),
                'ip' => $this->normalizeIp((string)($audit['ip'] ?? '')),
                'created_at_state' => $this->dateState($audit['created_at'] ?? ''),
            ];
        }
        return $rows;
    }

    private function normalizeActionEffect(array $data): array
    {
        return [
            'result' => (string)($data['result'] ?? ''),
            'revoked_sessions' => (int)($data['revoked_sessions'] ?? 0),
            'device_disabled' => (bool)($data['device_disabled'] ?? false),
            'card_disabled' => (bool)($data['card_disabled'] ?? false),
            'handled' => (bool)($data['handled'] ?? false),
        ];
    }

    private function normalizeError(array $step): array
    {
        $body = is_array($step['body'] ?? null) ? $step['body'] : [];
        return [
            'httpStatus' => (int)($step['httpStatus'] ?? 0),
            'code' => (int)($body['code'] ?? -1),
            'error' => (string)($body['error'] ?? ''),
        ];
    }

    private function messageFact(int $messageId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `status`, `read_at`, `handled_by`, `handled_at`, `archived_at` FROM `auth_messages` WHERE `id` = ?',
            [$messageId]
        );
        if (!is_array($row)) {
            return ['exists' => false];
        }
        return [
            'exists' => true,
            'status' => (string)($row['status'] ?? ''),
            'read_at_state' => $this->dateState($row['read_at'] ?? ''),
            'handled_by_state' => str_starts_with((string)($row['handled_by'] ?? ''), self::PREFIX . 'admin_') ? 'parity_admin' : ((string)($row['handled_by'] ?? '') === '' ? 'empty' : 'other'),
            'handled_at_state' => $this->dateState($row['handled_at'] ?? ''),
            'archived_at_state' => $this->dateState($row['archived_at'] ?? ''),
            'actions' => $this->countRows('SELECT COUNT(*) AS c FROM `auth_message_actions` WHERE `message_id` = ?', [$messageId]),
        ];
    }

    private function messageTargetFact(array $fixture): array
    {
        $session = $this->database->selectRowV2('SELECT `status` FROM `auth_sessions` WHERE `id` = ?', [$fixture['session_id']]);
        $device = $this->database->selectRowV2('SELECT `status` FROM `auth_devices` WHERE `id` = ?', [$fixture['device_id']]);
        $card = $this->database->selectRowV2('SELECT `status` FROM `auth_cards` WHERE `id` = ?', [$fixture['card_id']]);
        return [
            'message' => $this->messageFact((int)$fixture['message_id']),
            'session_status' => is_array($session) ? (int)($session['status'] ?? -1) : -1,
            'device_status' => is_array($device) ? (int)($device['status'] ?? -1) : -1,
            'card_status' => is_array($card) ? (int)($card['status'] ?? -1) : -1,
        ];
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
            [$username, $passwordHash, 'Parity Admin Messages', $this->rustBaseUrl]
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

    private function insertApp(string $appCode): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appCode,
                ClientApiConfig::generateToken(),
                'Parity Admin Messages',
                1,
                50,
                300,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                $this->json(ClientApiConfig::defaults()),
                '1.0.0',
                'local_key_v1',
                'rsa_oaep_aes_256_gcm',
                '',
                '',
                'admin messages parity',
            ]
        );
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
        $apps = $this->database->selectV2('SELECT `id` FROM `auth_apps` WHERE `app_code` LIKE ?', [self::PREFIX . 'APP_%']);
        foreach ($apps as $app) {
            $this->deleteAppRows((int)$app['id']);
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

    private function deleteAppRows(int $appId): void
    {
        $tables = [
            'auth_message_actions',
            'auth_messages',
            'auth_security_reports',
            'auth_sessions',
            'auth_devices',
            'auth_card_search_tokens',
            'auth_cards',
            'auth_audit_logs',
            'auth_remote_configs',
        ];
        foreach ($tables as $table) {
            if (!$this->tableExists($table)) {
                continue;
            }
            $this->exec("DELETE FROM `{$table}` WHERE `app_id` = ?", [$appId]);
        }
        $this->exec('DELETE FROM `auth_apps` WHERE `id` = ?', [$appId]);
    }

    private function rowExists(string $table, int $id): bool
    {
        return is_array($this->database->selectRowV2("SELECT `id` FROM `{$table}` WHERE `id` = ?", [$id]));
    }

    private function countRows(string $sql, array $params): int
    {
        $row = $this->database->selectRowV2($sql, $params);
        return is_array($row) ? (int)($row['c'] ?? -1) : -1;
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
        return $left === $right ? [] : [$path . ' php=' . $this->json($left) . ' rust=' . $this->json($right)];
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

    private function normalizeTargetText(string $value, array $target): string
    {
        return str_replace((string)$target['labelPrefix'], '<target>_', $value);
    }

    private function normalizeIp(string $ip): string
    {
        return $ip === '127.0.0.1' || $ip === '::1' ? '<local>' : $ip;
    }

    private function dateState(mixed $value): string
    {
        return trim((string)$value) === '' ? 'empty' : 'present';
    }

    private function dynamicId(mixed $value): array
    {
        $id = (int)$value;
        return ['type' => 'id', 'present' => $id > 0];
    }

    private function sortedKeys(array $row): array
    {
        $keys = array_map('strval', array_keys($row));
        sort($keys);
        return $keys;
    }

    private function printResult(string $name, array $result): void
    {
        echo strtoupper($name) . " " . $this->json($result) . "\n";
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

$check = new AdminMessagesParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
