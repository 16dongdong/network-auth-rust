<?php
declare(strict_types=1);

final class LocalParityRegressionSuite
{
    private const COMMANDS = [
        ['name' => 'install_readonly', 'script' => 'installReadonlyParityCheck.php', 'marker' => 'PARITY_OK install readonly flows'],
        ['name' => 'install_database_step', 'script' => 'installDatabaseStepParityCheck.php', 'marker' => 'PARITY_OK install database step valid submit'],
        ['name' => 'install_card_search_backfill', 'script' => 'installCardSearchBackfillParityCheck.php', 'marker' => 'PARITY_OK install card search token backfill'],
        ['name' => 'public_card_query', 'script' => 'publicCardQueryParityCheck.php', 'marker' => 'PARITY_OK public card query'],
        ['name' => 'client_session', 'script' => 'clientSessionParityCheck.php', 'marker' => 'PARITY_OK client plain session success path and security actions'],
        ['name' => 'admin_card_operations', 'script' => 'adminCardOperationsParityCheck.php', 'marker' => 'PARITY_OK admin card operations'],
        ['name' => 'admin_app_settings', 'script' => 'adminAppSettingsParityCheck.php', 'marker' => 'PARITY_OK admin app settings'],
        ['name' => 'admin_remote_variables', 'script' => 'adminRemoteVariablesParityCheck.php', 'marker' => 'PARITY_OK admin remote variables'],
        ['name' => 'admin_remote_api_tokens', 'script' => 'adminRemoteApiTokensParityCheck.php', 'marker' => 'PARITY_OK admin remote api tokens'],
        ['name' => 'admin_cloud_storage', 'script' => 'adminCloudStorageParityCheck.php', 'marker' => 'PARITY_OK admin cloud storage'],
        ['name' => 'admin_messages', 'script' => 'adminMessagesParityCheck.php', 'marker' => 'PARITY_OK admin messages'],
        ['name' => 'admin_general', 'script' => 'adminGeneralParityCheck.php', 'marker' => 'PARITY_OK admin general'],
        ['name' => 'admin_app_lifecycle', 'script' => 'adminAppLifecycleParityCheck.php', 'marker' => 'PARITY_OK admin app lifecycle'],
        ['name' => 'remote_api_apps', 'script' => 'remoteApiAppsParityCheck.php', 'marker' => 'PARITY_OK remote api apps'],
        ['name' => 'remote_api_config', 'script' => 'remoteApiConfigParityCheck.php', 'marker' => 'PARITY_OK remote api config'],
        ['name' => 'remote_api_cards', 'script' => 'remoteApiCardsParityCheck.php', 'marker' => 'PARITY_OK remote api cards'],
        ['name' => 'remote_api_cloud_storage', 'script' => 'remoteApiCloudStorageParityCheck.php', 'marker' => 'PARITY_OK remote api cloud storage'],
        ['name' => 'remote_api_variables', 'script' => 'remoteApiVariablesParityCheck.php', 'marker' => 'PARITY_OK remote api variables'],
    ];

    private readonly string $projectRoot;
    private readonly string $scriptsRoot;
    private readonly string $phpBinary;

    public function __construct()
    {
        $this->projectRoot = dirname(__DIR__);
        $this->scriptsRoot = __DIR__;
        $this->phpBinary = PHP_BINARY;
    }

    public function run(array $arguments): int
    {
        if (in_array('--help', $arguments, true) || in_array('-h', $arguments, true)) {
            $this->printHelp();
            return 0;
        }
        if (in_array('--list', $arguments, true)) {
            $this->printList();
            return 0;
        }

        $filters = $this->filters($arguments);
        $commands = $this->filteredCommands($filters);
        if ($commands === []) {
            fwrite(STDERR, "LOCAL_PARITY_SUITE_NO_MATCH filter=" . implode(',', $filters) . "\n");
            return 1;
        }

        $failures = [];
        foreach ($commands as $command) {
            $result = $this->runCommand($command);
            if ($result['ok']) {
                echo "LOCAL_PARITY_STEP_OK name={$command['name']} durationMs={$result['durationMs']}\n";
                continue;
            }
            $failures[] = $command['name'];
            fwrite(STDERR, "LOCAL_PARITY_STEP_FAILED name={$command['name']} exitCode={$result['exitCode']} durationMs={$result['durationMs']} output={$result['output']}\n");
            if (in_array('--stop-on-failure', $arguments, true)) {
                break;
            }
        }

        if ($failures !== []) {
            fwrite(STDERR, 'LOCAL_PARITY_REGRESSION_FAILED steps=' . implode(',', $failures) . "\n");
            return 1;
        }

        echo 'LOCAL_PARITY_REGRESSION_OK steps=' . count($commands) . "\n";
        return 0;
    }

    private function printHelp(): void
    {
        echo "Usage: php scripts/localParityRegressionSuite.php [--list] [--filter=name] [--stop-on-failure]\n";
        echo "Runs local PHP/Rust parity scripts against ACE_PHP_BASE_URL and ACE_RUST_BASE_URL.\n";
    }

    private function printList(): void
    {
        foreach (self::COMMANDS as $command) {
            echo $command['name'] . ' ' . $command['script'] . "\n";
        }
    }

    private function filters(array $arguments): array
    {
        $filters = [];
        foreach ($arguments as $argument) {
            if (str_starts_with($argument, '--filter=')) {
                $value = trim(substr($argument, strlen('--filter=')));
                if ($value !== '') {
                    $filters[] = strtolower($value);
                }
            }
        }
        return $filters;
    }

    private function filteredCommands(array $filters): array
    {
        if ($filters === []) {
            return self::COMMANDS;
        }
        return array_values(array_filter(self::COMMANDS, static function (array $command) use ($filters): bool {
            $haystack = strtolower($command['name'] . ' ' . $command['script']);
            foreach ($filters as $filter) {
                if (str_contains($haystack, $filter)) {
                    return true;
                }
            }
            return false;
        }));
    }

    private function runCommand(array $command): array
    {
        $startedAt = microtime(true);
        $scriptPath = $this->scriptsRoot . DIRECTORY_SEPARATOR . $command['script'];
        if (!is_file($scriptPath)) {
            return [
                'ok' => false,
                'exitCode' => -1,
                'durationMs' => 0,
                'output' => 'script missing: ' . $scriptPath,
            ];
        }

        $process = proc_open(
            [$this->phpBinary, $scriptPath],
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->projectRoot
        );
        if (!is_resource($process)) {
            return [
                'ok' => false,
                'exitCode' => -1,
                'durationMs' => 0,
                'output' => 'proc_open failed',
            ];
        }

        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        $output = trim((string)$stdout . "\n" . (string)$stderr);
        $durationMs = (int)round((microtime(true) - $startedAt) * 1000);

        return [
            'ok' => $exitCode === 0 && str_contains($output, $command['marker']),
            'exitCode' => $exitCode,
            'durationMs' => $durationMs,
            'output' => $this->compactOutput($output),
        ];
    }

    private function compactOutput(string $output): string
    {
        $normalized = preg_replace('/\s+/', ' ', trim($output)) ?? '';
        if (strlen($normalized) <= 1800) {
            return $normalized;
        }
        return substr($normalized, 0, 900) . ' ... ' . substr($normalized, -900);
    }
}

exit((new LocalParityRegressionSuite())->run(array_slice($_SERVER['argv'] ?? [], 1)));
