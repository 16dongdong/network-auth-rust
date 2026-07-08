<?php
declare(strict_types=1);

final class LocalPreProdGate
{
    private const RUST_CARGO = 'D:\\DevTools\\rust\\cargo\\bin\\cargo.exe';
    private const RUST_CARGO_HOME = 'D:\\DevTools\\rust\\cargo';
    private const RUSTUP_HOME = 'D:\\DevTools\\rust\\rustup';
    private const RELEASE_SELF_TEST = '/mnt/d/Desktop/0/网络验证rust/deploy/scripts/releaseScriptSelfTest.sh';

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

        $steps = $this->steps($arguments);
        if (in_array('--list', $arguments, true)) {
            foreach ($steps as $step) {
                echo $step['name'] . "\n";
            }
            return 0;
        }

        $filters = $this->filters($arguments);
        $skippedOptions = $this->skippedOptions($arguments);
        $steps = $this->filteredSteps($steps, $filters);
        if ($steps === []) {
            fwrite(STDERR, "LOCAL_PRE_PROD_GATE_NO_MATCH filter=" . implode(',', $filters) . "\n");
            return 1;
        }

        foreach ($steps as $step) {
            $result = $this->runStep($step);
            if ($result['ok']) {
                echo "LOCAL_PRE_PROD_STEP_OK name={$step['name']} durationMs={$result['durationMs']}\n";
                continue;
            }
            fwrite(STDERR, "LOCAL_PRE_PROD_STEP_FAILED name={$step['name']} exitCode={$result['exitCode']} durationMs={$result['durationMs']} output={$result['output']}\n");
            fwrite(STDERR, "LOCAL_PRE_PROD_GATE_FAILED step={$step['name']}\n");
            return 1;
        }

        if ($filters === [] && $skippedOptions === []) {
            echo 'LOCAL_PRE_PROD_GATE_OK steps=' . count($steps) . "\n";
            return 0;
        }

        $reasonParts = [];
        if ($filters !== []) {
            $reasonParts[] = 'filters=' . implode(',', $filters);
        }
        if ($skippedOptions !== []) {
            $reasonParts[] = 'skipped=' . implode(',', $skippedOptions);
        }
        echo 'LOCAL_PRE_PROD_PARTIAL_OK steps=' . count($steps) . ' ' . implode(' ', $reasonParts) . "\n";
        return 0;
    }

    private function printHelp(): void
    {
        echo "Usage: php scripts/localPreProdGate.php [--list] [--filter=name] [--skip-public-runtime-self-test] [--skip-public-runtime] [--skip-live] [--skip-cargo] [--skip-release-self-test]\n";
        echo "Runs the local gate required before considering prod cutover.\n";
        echo "--skip-public-runtime-self-test is only for debugging a broken local PHP server environment.\n";
        echo "--skip-public-runtime is only for offline script validation; full pre-prod gate must include public runtime readiness.\n";
        echo "--skip-live is only for local script validation; full pre-prod gate must include live smoke.\n";
    }

    private function steps(array $arguments): array
    {
        $steps = [
            [
                'name' => 'local_pre_prod_gate_self_test',
                'command' => [$this->phpBinary, $this->scriptPath('localPreProdGateSelfTest.php')],
                'marker' => 'LOCAL_PRE_PROD_SELF_TEST_OK',
            ],
            [
                'name' => 'local_parity_regression',
                'command' => [$this->phpBinary, $this->scriptPath('localParityRegressionSuite.php'), '--stop-on-failure'],
                'marker' => 'LOCAL_PARITY_REGRESSION_OK',
            ],
        ];

        if (!in_array('--skip-public-runtime-self-test', $arguments, true)) {
            $steps[] = [
                'name' => 'public_runtime_readiness_self_test',
                'command' => [$this->phpBinary, $this->scriptPath('publicRuntimeReadinessGateSelfTest.php')],
                'marker' => 'PUBLIC_RUNTIME_SELF_TEST_OK',
            ];
        }

        if (!in_array('--skip-public-runtime', $arguments, true)) {
            $steps[] = [
                'name' => 'public_runtime_readiness',
                'command' => [$this->phpBinary, $this->scriptPath('publicRuntimeReadinessGate.php')],
                'marker' => 'PUBLIC_RUNTIME_READINESS_OK',
            ];
        }

        if (!in_array('--skip-public-runtime', $arguments, true)) {
            $steps[] = [
                'name' => 'prod_cutover_sequence_self_test',
                'command' => [$this->phpBinary, $this->scriptPath('prodCutoverSequenceGateSelfTest.php')],
                'marker' => 'PROD_CUTOVER_SEQUENCE_SELF_TEST_OK',
            ];
            $steps[] = [
                'name' => 'prod_cutover_sequence_precheck',
                'command' => [$this->phpBinary, $this->scriptPath('prodCutoverSequenceGate.php')],
                'marker' => 'PROD_CUTOVER_SEQUENCE_PRE_OK',
            ];
        }

        if (!in_array('--skip-live', $arguments, true)) {
            $steps[] = [
                'name' => 'remaining_live_smoke',
                'command' => [$this->phpBinary, $this->scriptPath('remainingLiveSmokeGate.php')],
                'marker' => 'REMAINING_LIVE_SMOKE_READY',
            ];
        }

        if (!in_array('--skip-cargo', $arguments, true)) {
            array_push(
                $steps,
                ['name' => 'cargo_fmt', 'command' => [$this->cargoBinary(), 'fmt', '--check'], 'marker' => null],
                ['name' => 'cargo_check', 'command' => [$this->cargoBinary(), 'check', '-j1', '--quiet'], 'marker' => null],
                ['name' => 'cargo_test_lib', 'command' => [$this->cargoBinary(), 'test', '-j1', '--lib', '--quiet'], 'marker' => null],
                ['name' => 'cargo_test_card_search', 'command' => [$this->cargoBinary(), 'test', '-j1', 'card_search', '--quiet'], 'marker' => null],
                ['name' => 'cargo_test_deploy', 'command' => [$this->cargoBinary(), 'test', '-j1', 'deploy', '--quiet'], 'marker' => null],
                ['name' => 'cargo_test_install', 'command' => [$this->cargoBinary(), 'test', '-j1', 'install', '--quiet'], 'marker' => null],
            );
        }

        if (!in_array('--skip-release-self-test', $arguments, true)) {
            $steps[] = [
                'name' => 'release_script_self_test',
                'command' => ['wsl.exe', 'bash', self::RELEASE_SELF_TEST],
                'marker' => 'RELEASE_SCRIPT_SELF_TEST_OK',
            ];
        }

        return $steps;
    }

    private function filters(array $arguments): array
    {
        $filters = [];
        foreach ($arguments as $argument) {
            if (str_starts_with($argument, '--filter=')) {
                $filter = trim(substr($argument, strlen('--filter=')));
                if ($filter !== '') {
                    $filters[] = strtolower($filter);
                }
            }
        }
        return $filters;
    }

    private function skippedOptions(array $arguments): array
    {
        $skippedOptions = [];
        foreach ($arguments as $argument) {
            if (str_starts_with($argument, '--skip-')) {
                $skippedOptions[] = substr($argument, strlen('--skip-'));
            }
        }
        return array_values(array_unique($skippedOptions));
    }

    private function filteredSteps(array $steps, array $filters): array
    {
        if ($filters === []) {
            return $steps;
        }
        return array_values(array_filter($steps, static function (array $step) use ($filters): bool {
            $name = strtolower((string)$step['name']);
            foreach ($filters as $filter) {
                if (str_contains($name, $filter)) {
                    return true;
                }
            }
            return false;
        }));
    }

    private function runStep(array $step): array
    {
        $startedAt = microtime(true);
        $process = proc_open(
            $step['command'],
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->projectRoot,
            $this->environment()
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
        $marker = $step['marker'];

        return [
            'ok' => $exitCode === 0 && ($marker === null || str_contains($output, $marker)),
            'exitCode' => $exitCode,
            'durationMs' => $durationMs,
            'output' => $this->compactOutput($output),
        ];
    }

    private function scriptPath(string $scriptName): string
    {
        return $this->scriptsRoot . DIRECTORY_SEPARATOR . $scriptName;
    }

    private function cargoBinary(): string
    {
        return is_file(self::RUST_CARGO) ? self::RUST_CARGO : 'cargo';
    }

    private function environment(): array
    {
        $environment = getenv();
        $path = (string)($environment['Path'] ?? $environment['PATH'] ?? '');
        $environment['CARGO_HOME'] = self::RUST_CARGO_HOME;
        $environment['RUSTUP_HOME'] = self::RUSTUP_HOME;
        $environment['Path'] = dirname(self::RUST_CARGO) . ';' . $path;
        $environment['PATH'] = $environment['Path'];
        return $environment;
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

exit((new LocalPreProdGate())->run(array_slice($_SERVER['argv'] ?? [], 1)));
