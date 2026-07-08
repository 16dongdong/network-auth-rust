<?php
declare(strict_types=1);

define('NETWORK_AUTH_API', true);

$phpProjectRoot = getenv('ACE_PHP_ROOT') ?: 'D:\\Desktop\\0\\ACE网络验证';
require_once $phpProjectRoot . DIRECTORY_SEPARATOR . 'bootstrap' . DIRECTORY_SEPARATOR . 'app.php';

use NetworkAuth\Security\Crypto;
use NetworkAuth\Security\RequestSigner;
use NetworkAuth\Support\ClientApiConfig;

final class AdminCardOperationsParityCheck
{
    private const PREFIX = 'E2E_ADMIN_CARD_OPS_';
    private const CUSTOM_CARD_KEYS = [
        'timeA' => 'E2E_ADMIN_CARD_TIME_A',
        'timeB' => 'E2E_ADMIN_CARD_TIME_B',
        'countA' => 'E2E_ADMIN_CARD_COUNT_A',
        'countB' => 'E2E_ADMIN_CARD_COUNT_B',
    ];
    private const RANGE_CARD_KEYS = [
        'resetTime' => 'E2E_RANGE_TIME_RESET',
        'addTimeChange' => 'E2E_RANGE_TIME_ADD_CHANGE',
        'addTimeLimit' => 'E2E_RANGE_TIME_ADD_LIMIT',
        'reduceTimeChange' => 'E2E_RANGE_TIME_REDUCE_CHANGE',
        'reduceTimeFloor' => 'E2E_RANGE_TIME_REDUCE_FLOOR',
        'countResetChange' => 'E2E_RANGE_COUNT_RESET_CHANGE',
        'countResetNoop' => 'E2E_RANGE_COUNT_RESET_NOOP',
        'disableChange' => 'E2E_RANGE_DISABLE_CHANGE',
        'disableNoop' => 'E2E_RANGE_DISABLE_NOOP',
        'enableChange' => 'E2E_RANGE_ENABLE_CHANGE',
        'enableNoop' => 'E2E_RANGE_ENABLE_NOOP',
        'deleteA' => 'E2E_RANGE_DELETE_A',
        'deleteB' => 'E2E_RANGE_DELETE_B',
    ];
    private const RUST_SAFETY_REDUCE_CARD_KEY = 'E2E_RUST_SAFE_REDUCE_UNDERFLOW';
    private const MAX_CARD_DURATION_SECONDS = 315360000;

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
            $phpTarget = $this->createTarget('php', $this->phpBaseUrl);
            $rustTarget = $this->createTarget('rust', $this->rustBaseUrl);
            $phpResult = $this->runTarget($phpTarget, $session);
            $rustResult = $this->runTarget($rustTarget, $session);
            $this->printResult('php', $phpResult);
            $this->printResult('rust', $rustResult);
            $diffs = $this->diff($phpResult, $rustResult, 'adminCardOperations');
            if ($diffs !== []) {
                foreach ($diffs as $diff) {
                    fwrite(STDERR, "DIFF {$diff}\n");
                }
                return 1;
            }
            $rustSafetyResult = $this->runRustSafetyChecks($session);
            $this->printResult('rustSafety', $rustSafetyResult);
            echo "PARITY_OK admin card operations\n";
            return 0;
        } finally {
            if (!$keepData) {
                $this->cleanup();
            }
        }
    }

    private function createTarget(string $name, string $baseUrl): array
    {
        $appCode = self::PREFIX . strtoupper($name) . '_' . $this->randomAlpha(8);
        $this->insertApp($appCode);
        return [
            'name' => $name,
            'baseUrl' => rtrim($baseUrl, '/'),
            'appCode' => $appCode,
        ];
    }

    private function runTarget(array $target, array $session): array
    {
        $steps = [];
        $steps['createGenerated'] = $this->normalizeGeneratedCreate($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/create',
            [
                'app_code' => $target['appCode'],
                'card_type' => 'permanent',
                'count' => 2,
                'prefix' => 'GEN',
                'card_structure' => 'digit',
                'card_length' => 12,
                'max_devices' => 4,
                'unbind_limit' => 1,
            ]
        )));
        $steps['importTime'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/import',
            [
                'app_code' => $target['appCode'],
                'card_type' => 'time',
                'duration_seconds' => 60,
                'max_devices' => 3,
                'unbind_limit' => 2,
                'custom_cards' => implode("\n", [
                    self::CUSTOM_CARD_KEYS['timeA'],
                    self::CUSTOM_CARD_KEYS['timeB'],
                    self::CUSTOM_CARD_KEYS['timeA'],
                ]),
            ]
        ));
        $steps['importCount'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/import',
            [
                'app_code' => $target['appCode'],
                'card_type' => 'count',
                'total_uses' => 5,
                'custom_cards' => implode(';', [
                    self::CUSTOM_CARD_KEYS['countA'],
                    self::CUSTOM_CARD_KEYS['countB'],
                ]),
            ]
        ));

        $cards = $this->cardsByKey($this->listCards($target, $session));
        $timeAId = $this->cardId($cards, 'timeA');
        $timeBId = $this->cardId($cards, 'timeB');
        $countAId = $this->cardId($cards, 'countA');
        $countBId = $this->cardId($cards, 'countB');

        $steps['disableOne'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/status', [
            'card_id' => $timeAId,
            'status' => 2,
        ]));
        $steps['enableOne'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/status', [
            'card_id' => $timeAId,
            'status' => 0,
        ]));
        $steps['adjustAdd'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/adjust-time', [
            'card_id' => $timeBId,
            'direction' => 'add',
            'duration_seconds' => 120,
        ]));
        $steps['adjustReduce'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/adjust-time', [
            'card_id' => $timeBId,
            'direction' => 'reduce',
            'duration_seconds' => 500,
        ]));
        $steps['adjustReset'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/adjust-time', [
            'card_id' => $timeBId,
            'direction' => 'reset',
            'duration_seconds' => 3600,
        ]));
        $steps['resetUses'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/reset-uses', [
            'card_id' => $countAId,
        ]));
        $steps['batchDisable'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/batch-status', [
            'app_code' => $target['appCode'],
            'card_ids' => [$timeAId, $countBId, $countBId],
            'status' => 2,
        ]));
        $steps['batchEnable'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/batch-status', [
            'app_code' => $target['appCode'],
            'card_ids' => [$timeAId, $countBId],
            'status' => 0,
        ]));
        $steps['batchResetUses'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/batch-reset-uses', [
            'app_code' => $target['appCode'],
            'card_ids' => [$timeAId, $countAId, $countBId],
        ]));
        foreach ($this->runRangeOperations($target, $session) as $stepName => $stepData) {
            $steps[$stepName] = $stepData;
        }
        $timeADevices = $this->insertDeviceFixtures($target['appCode'], $timeAId, 'Time A');
        $steps['devicesBefore'] = $this->normalizeDeviceList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/devices',
            [
                'app_code' => $target['appCode'],
                'card_id' => $timeAId,
            ]
        )));
        $steps['countCardDevices'] = $this->normalizeDeviceList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/devices',
            [
                'app_code' => $target['appCode'],
                'card_id' => $countAId,
            ]
        )));
        $steps['batchDeviceDisable'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/devices/batch-status', [
            'app_code' => $target['appCode'],
            'card_ids' => [$timeAId, $countAId],
            'status' => 0,
        ]));
        $steps['devicesAfterDisable'] = $this->normalizeDeviceList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/devices',
            [
                'app_code' => $target['appCode'],
                'card_id' => $timeAId,
            ]
        )));
        $steps['batchDeviceEnable'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/devices/batch-status', [
            'app_code' => $target['appCode'],
            'card_ids' => [$timeAId],
            'status' => 1,
        ]));
        $steps['unbindOneDevice'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/devices/unbind', [
            'device_id' => $timeADevices[1],
        ]));
        $steps['devicesAfterUnbindOne'] = $this->normalizeDeviceList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/devices',
            [
                'app_code' => $target['appCode'],
                'card_id' => $timeAId,
            ]
        )));
        $steps['unbindAllDevices'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/devices/unbind-all', [
            'app_code' => $target['appCode'],
            'card_id' => $timeAId,
        ]));
        $steps['devicesAfterUnbindAll'] = $this->normalizeDeviceList($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/devices',
            [
                'app_code' => $target['appCode'],
                'card_id' => $timeAId,
            ]
        )));
        $this->insertDeviceFixtures($target['appCode'], $timeBId, 'Time B');
        $steps['batchDeviceUnbind'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/devices/batch-unbind', [
            'app_code' => $target['appCode'],
            'card_ids' => [$timeBId, $countAId],
        ]));
        $steps['exportSelected'] = $this->normalizeExport($this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/export',
            [
                'app_code' => $target['appCode'],
                'status' => '',
                'duration_category' => '',
                'keyword' => '',
                'card_ids' => [$timeAId, $countAId],
            ]
        )));
        $steps['deleteOne'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/delete', [
            'app_code' => $target['appCode'],
            'card_ids' => [$timeBId],
        ]));

        return [
            'steps' => $steps,
            'cards' => $this->customCardFacts($this->cardsByKey($this->listCards($target, $session))),
        ];
    }

    private function runRangeOperations(array $target, array $session): array
    {
        $steps = [];
        $steps['rangeImportTime'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/import',
            [
                'app_code' => $target['appCode'],
                'card_type' => 'time',
                'duration_seconds' => 60,
                'max_devices' => 2,
                'custom_cards' => implode("\n", [
                    self::RANGE_CARD_KEYS['resetTime'],
                    self::RANGE_CARD_KEYS['addTimeChange'],
                    self::RANGE_CARD_KEYS['addTimeLimit'],
                    self::RANGE_CARD_KEYS['reduceTimeChange'],
                    self::RANGE_CARD_KEYS['reduceTimeFloor'],
                ]),
            ]
        ));
        $steps['rangeImportCount'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/import',
            [
                'app_code' => $target['appCode'],
                'card_type' => 'count',
                'total_uses' => 5,
                'custom_cards' => implode("\n", [
                    self::RANGE_CARD_KEYS['countResetChange'],
                    self::RANGE_CARD_KEYS['countResetNoop'],
                ]),
            ]
        ));
        $steps['rangeImportPermanent'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/import',
            [
                'app_code' => $target['appCode'],
                'card_type' => 'permanent',
                'max_devices' => 2,
                'custom_cards' => implode("\n", [
                    self::RANGE_CARD_KEYS['disableChange'],
                    self::RANGE_CARD_KEYS['disableNoop'],
                    self::RANGE_CARD_KEYS['enableChange'],
                    self::RANGE_CARD_KEYS['enableNoop'],
                    self::RANGE_CARD_KEYS['deleteA'],
                    self::RANGE_CARD_KEYS['deleteB'],
                ]),
            ]
        ));

        $cards = $this->cardsByKey($this->listCards($target, $session));
        $this->setRangeCardStates($target['appCode'], $cards);
        $this->insertDeviceFixtures(
            $target['appCode'],
            $this->cardIdByExactKey($cards, self::RANGE_CARD_KEYS['resetTime']),
            'Range Reset'
        );

        $steps['rangeResetDuration'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'reset_duration',
            'activated_start' => '2024-01-10',
            'activated_end' => '2024-01-10',
            'duration_seconds' => 7200,
        ]));
        $steps['rangeAddDuration'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'add_duration',
            'activated_start' => '2024-02-10',
            'activated_end' => '2024-02-10',
            'duration_seconds' => 3600,
        ]));
        $steps['rangeReduceDuration'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'reduce_duration',
            'activated_start' => '2024-03-10',
            'activated_end' => '2024-03-10',
            'duration_seconds' => 60,
        ]));
        $steps['rangeResetUses'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'reset_uses',
            'activated_start' => '2024-04-10',
            'activated_end' => '2024-04-10',
        ]));
        $steps['rangeDisable'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'disable',
            'activated_start' => '2024-05-10',
            'activated_end' => '2024-05-10',
        ]));
        $steps['rangeEnable'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'enable',
            'activated_start' => '2024-06-10',
            'activated_end' => '2024-06-10',
        ]));
        $steps['rangeDelete'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'delete',
            'activated_start' => '2024-07-10',
            'activated_end' => '2024-07-10',
        ]));
        $steps['rangeFacts'] = $this->rangeCardFacts($target['appCode']);
        return $steps;
    }

    private function runRustSafetyChecks(array $session): array
    {
        $target = $this->createTarget('safe', $this->rustBaseUrl);
        $steps = [];
        $steps['importReduceUnderflowCard'] = $this->successData($this->adminRequest(
            $target,
            $session,
            '/admin/cards/import',
            [
                'app_code' => $target['appCode'],
                'card_type' => 'time',
                'duration_seconds' => 300,
                'custom_cards' => self::RUST_SAFETY_REDUCE_CARD_KEY,
            ]
        ));
        $cards = $this->cardsByKey($this->listCards($target, $session));
        $appId = $this->appId($target['appCode']);
        $cardId = $this->cardIdByExactKey($cards, self::RUST_SAFETY_REDUCE_CARD_KEY);
        $this->exec(
            'UPDATE `auth_cards` SET `status` = ?, `used_at` = ?, `duration_seconds` = ? WHERE `app_id` = ? AND `id` = ?',
            [1, '2024-08-10 12:00:00', 300, $appId, $cardId]
        );
        $steps['reduceUnderflowSafe'] = $this->successData($this->adminRequest($target, $session, '/admin/cards/range-operation', [
            'app_code' => $target['appCode'],
            'operation' => 'reduce_duration',
            'activated_start' => '2024-08-10',
            'activated_end' => '2024-08-10',
            'duration_seconds' => 3600,
        ]));
        $steps['reduceUnderflowFact'] = $this->singleCardFact($target['appCode'], self::RUST_SAFETY_REDUCE_CARD_KEY);
        $expected = [
            'operation' => 'reduce_duration',
            'matched' => 1,
            'affected' => 1,
        ];
        if ($steps['reduceUnderflowSafe'] !== $expected) {
            throw new RuntimeException('rust reduce underflow response mismatch: ' . $this->json($steps['reduceUnderflowSafe']));
        }
        if (($steps['reduceUnderflowFact']['duration_seconds'] ?? null) !== 60) {
            throw new RuntimeException('rust reduce underflow did not clamp to minimum duration: ' . $this->json($steps['reduceUnderflowFact']));
        }
        return $steps;
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

    private function listCards(array $target, array $session): array
    {
        $data = $this->successData($this->adminRequest($target, $session, '/admin/cards/list', [
            'app_code' => $target['appCode'],
            'page' => 1,
            'limit' => 50,
            'status' => '',
            'duration_category' => '',
            'keyword' => '',
        ]));
        return $data['cards'] ?? [];
    }

    private function cardsByKey(array $cards): array
    {
        $result = [];
        foreach ($cards as $card) {
            if (!is_array($card)) {
                continue;
            }
            $key = (string)($card['card_key'] ?? '');
            if ($key !== '') {
                $result[$key] = $card;
            }
        }
        ksort($result);
        return $result;
    }

    private function cardId(array $cards, string $keyName): int
    {
        $cardKey = self::CUSTOM_CARD_KEYS[$keyName];
        if (!isset($cards[$cardKey]['id'])) {
            throw new RuntimeException("missing card {$cardKey}");
        }
        return (int)$cards[$cardKey]['id'];
    }

    private function cardIdByExactKey(array $cards, string $cardKey): int
    {
        if (!isset($cards[$cardKey]['id'])) {
            throw new RuntimeException("missing card {$cardKey}");
        }
        return (int)$cards[$cardKey]['id'];
    }

    private function setRangeCardStates(string $appCode, array $cards): void
    {
        $states = [
            'resetTime' => ['status' => 1, 'used_at' => '2024-01-10 12:00:00', 'duration_seconds' => 3600, 'total_uses' => 0, 'remaining_uses' => 0],
            'addTimeChange' => ['status' => 1, 'used_at' => '2024-02-10 12:00:00', 'duration_seconds' => 60, 'total_uses' => 0, 'remaining_uses' => 0],
            'addTimeLimit' => ['status' => 1, 'used_at' => '2024-02-10 13:00:00', 'duration_seconds' => self::MAX_CARD_DURATION_SECONDS, 'total_uses' => 0, 'remaining_uses' => 0],
            'reduceTimeChange' => ['status' => 1, 'used_at' => '2024-03-10 12:00:00', 'duration_seconds' => 3600, 'total_uses' => 0, 'remaining_uses' => 0],
            'reduceTimeFloor' => ['status' => 1, 'used_at' => '2024-03-10 13:00:00', 'duration_seconds' => 60, 'total_uses' => 0, 'remaining_uses' => 0],
            'countResetChange' => ['status' => 1, 'used_at' => '2024-04-10 12:00:00', 'duration_seconds' => 0, 'total_uses' => 5, 'remaining_uses' => 1],
            'countResetNoop' => ['status' => 1, 'used_at' => '2024-04-10 13:00:00', 'duration_seconds' => 0, 'total_uses' => 5, 'remaining_uses' => 5],
            'disableChange' => ['status' => 1, 'used_at' => '2024-05-10 12:00:00', 'duration_seconds' => 0, 'total_uses' => 0, 'remaining_uses' => 0],
            'disableNoop' => ['status' => 2, 'used_at' => '2024-05-10 13:00:00', 'duration_seconds' => 0, 'total_uses' => 0, 'remaining_uses' => 0],
            'enableChange' => ['status' => 2, 'used_at' => '2024-06-10 12:00:00', 'duration_seconds' => 0, 'total_uses' => 0, 'remaining_uses' => 0],
            'enableNoop' => ['status' => 1, 'used_at' => '2024-06-10 13:00:00', 'duration_seconds' => 0, 'total_uses' => 0, 'remaining_uses' => 0],
            'deleteA' => ['status' => 1, 'used_at' => '2024-07-10 12:00:00', 'duration_seconds' => 0, 'total_uses' => 0, 'remaining_uses' => 0],
            'deleteB' => ['status' => 2, 'used_at' => '2024-07-10 13:00:00', 'duration_seconds' => 0, 'total_uses' => 0, 'remaining_uses' => 0],
        ];
        $appId = $this->appId($appCode);
        foreach ($states as $keyName => $state) {
            $this->exec(
                'UPDATE `auth_cards` SET `status` = ?, `used_at` = ?, `duration_seconds` = ?, `total_uses` = ?, `remaining_uses` = ? WHERE `app_id` = ? AND `id` = ?',
                [
                    $state['status'],
                    $state['used_at'],
                    $state['duration_seconds'],
                    $state['total_uses'],
                    $state['remaining_uses'],
                    $appId,
                    $this->cardIdByExactKey($cards, self::RANGE_CARD_KEYS[$keyName]),
                ]
            );
        }
    }

    private function rangeCardFacts(string $appCode): array
    {
        $appId = $this->appId($appCode);
        $facts = [];
        foreach (self::RANGE_CARD_KEYS as $keyName => $cardKey) {
            $facts[$keyName] = $this->singleCardFactByAppId($appId, $appCode, $cardKey);
        }
        return $facts;
    }

    private function singleCardFact(string $appCode, string $cardKey): array
    {
        return $this->singleCardFactByAppId($this->appId($appCode), $appCode, $cardKey);
    }

    private function singleCardFactByAppId(int $appId, string $appCode, string $cardKey): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `id`, `card_hash`, `card_type`, `status`, `duration_seconds`, `total_uses`, `remaining_uses`, `used_at` FROM `auth_cards` WHERE `app_id` = ? AND `card_hash` = ?',
            [$appId, $this->cardHash($appCode, $cardKey)]
        );
        if (!is_array($row) || !isset($row['id'])) {
            return ['exists' => false];
        }
        return [
            'exists' => true,
            'card_type' => (string)$row['card_type'],
            'status' => (int)$row['status'],
            'duration_seconds' => (int)$row['duration_seconds'],
            'total_uses' => (int)$row['total_uses'],
            'remaining_uses' => (int)$row['remaining_uses'],
            'used_at' => $row['used_at'] === null ? '' : (string)$row['used_at'],
            'active_sessions' => $this->activeSessionCount($appId, (int)$row['id'], (string)$row['card_hash']),
        ];
    }

    private function activeSessionCount(int $appId, int $cardId, string $cardHash): int
    {
        $row = $this->database->selectRowV2(
            'SELECT COUNT(*) AS `total` FROM `auth_sessions` WHERE `app_id` = ? AND `status` = 1 AND (`card_id` = ? OR `card_hash` = ?)',
            [$appId, $cardId, $cardHash]
        );
        return is_array($row) ? (int)($row['total'] ?? 0) : 0;
    }

    private function cardHash(string $appCode, string $cardKey): string
    {
        return Crypto::sha256($appCode . ':' . $cardKey);
    }

    private function customCardFacts(array $cards): array
    {
        $facts = [];
        foreach (self::CUSTOM_CARD_KEYS as $name => $cardKey) {
            if (!isset($cards[$cardKey])) {
                $facts[$name] = ['exists' => false];
                continue;
            }
            $card = $cards[$cardKey];
            $facts[$name] = [
                'exists' => true,
                'card_type' => $card['card_type'] ?? null,
                'status' => $card['status'] ?? null,
                'duration_seconds' => $card['duration_seconds'] ?? null,
                'total_uses' => $card['total_uses'] ?? null,
                'remaining_uses' => $card['remaining_uses'] ?? null,
                'max_devices' => $card['max_devices'] ?? null,
                'unbind_limit' => $card['unbind_limit'] ?? null,
                'duration_category' => $card['duration_category'] ?? null,
                'duration_text' => $card['duration_text'] ?? null,
                'remaining_text' => $card['remaining_text'] ?? null,
                'expires_at_empty' => (($card['expires_at'] ?? '') === ''),
            ];
        }
        return $facts;
    }

    private function normalizeDeviceList(array $data): array
    {
        $devices = [];
        foreach (($data['devices'] ?? []) as $device) {
            if (!is_array($device)) {
                continue;
            }
            $devices[] = [
                'device_name' => $device['device_name'] ?? null,
                'card_fingerprint' => $device['card_fingerprint'] ?? null,
                'install_id' => $device['install_id'] ?? null,
                'machine_profile_hash' => $device['machine_profile_hash'] ?? null,
                'bind_ip' => $device['bind_ip'] ?? null,
                'bind_region' => $device['bind_region'] ?? null,
                'status' => $device['status'] ?? null,
            ];
        }
        usort(
            $devices,
            static fn(array $left, array $right): int => strcmp((string)$left['device_name'], (string)$right['device_name'])
        );
        return [
            'count' => count($devices),
            'devices' => $devices,
        ];
    }

    private function normalizeGeneratedCreate(array $data): array
    {
        $cards = array_values(array_map('strval', $data['cards'] ?? []));
        return [
            'card_count' => count($cards),
            'cards_match_rule' => $this->generatedCardsMatchRule($cards),
            'card_type' => $data['card_type'] ?? null,
            'duration_seconds' => $data['duration_seconds'] ?? null,
            'total_uses' => $data['total_uses'] ?? null,
            'max_devices' => $data['max_devices'] ?? null,
            'unbind_limit' => $data['unbind_limit'] ?? null,
        ];
    }

    private function generatedCardsMatchRule(array $cards): bool
    {
        if (count($cards) !== 2) {
            return false;
        }
        foreach ($cards as $card) {
            if (preg_match('/^GEN-[0-9]{12}$/', $card) !== 1) {
                return false;
            }
        }
        return true;
    }

    private function normalizeExport(array $data): array
    {
        $content = base64_decode((string)($data['content_base64'] ?? ''), true);
        $lines = $content === false ? [] : preg_split('/\r?\n/', trim($content));
        $lines = array_values(array_filter($lines, static fn(string $line): bool => $line !== ''));
        sort($lines);
        return [
            'mime' => $data['mime'] ?? null,
            'rows' => $data['rows'] ?? null,
            'skipped_unrecoverable' => $data['skipped_unrecoverable'] ?? null,
            'content_lines' => $lines,
        ];
    }

    private function createAdminSession(): array
    {
        $username = self::PREFIX . 'admin_' . strtolower($this->randomAlpha(8));
        $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
        $this->exec(
            'INSERT INTO `sub_admin` (`username`, `password`, `hostname`, `siteurl`) VALUES (?, ?, ?, ?)',
            [$username, $passwordHash, 'Parity Admin', $this->rustBaseUrl]
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

    private function insertApp(string $appCode): void
    {
        $this->exec(
            'INSERT INTO `auth_apps` (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appCode,
                ClientApiConfig::generateToken(),
                'Parity Admin Card Ops',
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
                'admin card operations parity',
            ]
        );
    }

    private function insertDeviceFixtures(string $appCode, int $cardId, string $fixtureName): array
    {
        $appId = $this->appId($appCode);
        $card = $this->cardRow($appId, $cardId);
        $primaryDeviceId = $this->insertDevice($appCode, $appId, $card, "Parity Device {$fixtureName} Primary", true);
        $legacyDeviceId = $this->insertDevice($appCode, $appId, $card, "Parity Device {$fixtureName} Legacy", false);
        $this->insertActiveSession($appCode, $appId, $card, $primaryDeviceId);
        return [$primaryDeviceId, $legacyDeviceId];
    }

    private function insertDevice(string $appCode, int $appId, array $card, string $deviceName, bool $useCardId): int
    {
        return (int)$this->exec(
            'INSERT INTO `auth_devices` (`app_id`, `account_id`, `card_id`, `card_hash`, `device_hash`, `device_name`, `install_id`, `device_public_key`, `device_key_alg`, `machine_profile_hash`, `bind_ip`, `bind_region`, `risk_level`, `status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                null,
                $useCardId ? (int)$card['id'] : null,
                (string)$card['card_hash'],
                hash('sha256', $deviceName),
                $deviceName,
                'INSTALL_' . strtoupper(substr(hash('sha256', $deviceName), 0, 24)),
                '',
                'local_key_v1',
                hash('sha256', 'machine:' . $deviceName),
                '127.0.0.1',
                'Local',
                0,
                1,
            ]
        );
    }

    private function insertActiveSession(string $appCode, int $appId, array $card, int $deviceId): void
    {
        $this->exec(
            'INSERT INTO `auth_sessions` (`app_id`, `account_id`, `device_id`, `card_id`, `card_hash`, `card_fingerprint`, `token_hash`, `request_counter`, `proof_mode`, `ticket_hash`, `ticket_expires_at`, `status`, `ip`, `expires_at`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $appId,
                null,
                $deviceId,
                (int)$card['id'],
                (string)$card['card_hash'],
                (string)$card['card_fingerprint'],
                hash('sha256', $appCode . ':session:' . $deviceId),
                1,
                'local_key_v1',
                null,
                null,
                1,
                '127.0.0.1',
                date('Y-m-d H:i:s', time() + 3600),
            ]
        );
    }

    private function appId(string $appCode): int
    {
        $row = $this->database->selectRowV2('SELECT `id` FROM `auth_apps` WHERE `app_code` = ?', [$appCode]);
        if (!is_array($row) || !isset($row['id'])) {
            throw new RuntimeException("missing app {$appCode}");
        }
        return (int)$row['id'];
    }

    private function cardRow(int $appId, int $cardId): array
    {
        $row = $this->database->selectRowV2(
            'SELECT `id`, `app_id`, `card_hash`, `card_fingerprint` FROM `auth_cards` WHERE `app_id` = ? AND `id` = ?',
            [$appId, $cardId]
        );
        if (!is_array($row) || !isset($row['id'], $row['card_hash'], $row['card_fingerprint'])) {
            throw new RuntimeException("missing card {$cardId}");
        }
        return $row;
    }

    private function cleanup(): void
    {
        $this->deleteAdminSessions();
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

    private function jsonScalar(mixed $value): string
    {
        return $this->json($value);
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

$check = new AdminCardOperationsParityCheck(
    $DB,
    (string)SYS_KEY,
    getenv('ACE_PHP_BASE_URL') ?: 'http://127.0.0.1:18081',
    getenv('ACE_RUST_BASE_URL') ?: 'http://127.0.0.1:18080'
);
exit($check->run());
