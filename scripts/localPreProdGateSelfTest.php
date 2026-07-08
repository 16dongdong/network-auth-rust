<?php
declare(strict_types=1);

final class LocalPreProdGateSelfTest
{
    private const REQUIRED_STEPS = [
        'local_pre_prod_gate_self_test',
        'local_parity_regression',
        'public_runtime_readiness_self_test',
        'public_runtime_readiness',
        'prod_cutover_sequence_self_test',
        'prod_cutover_sequence_precheck',
        'remaining_live_smoke',
        'cargo_fmt',
        'cargo_check',
        'cargo_test_lib',
        'cargo_test_card_search',
        'cargo_test_deploy',
        'cargo_test_install',
        'release_script_self_test',
    ];

    private readonly string $projectRoot;
    private readonly string $phpBinary;

    public function __construct()
    {
        $this->projectRoot = dirname(__DIR__);
        $this->phpBinary = PHP_BINARY;
    }

    public function run(): int
    {
        $this->assertStepList();
        echo "LOCAL_PRE_PROD_SELF_TEST_SCENARIO_OK scenario=step_list\n";

        $this->assertPartialRun();
        echo "LOCAL_PRE_PROD_SELF_TEST_SCENARIO_OK scenario=partial_run_marker\n";

        $this->assertNoMatchFailure();
        echo "LOCAL_PRE_PROD_SELF_TEST_SCENARIO_OK scenario=no_match_failure\n";

        echo "LOCAL_PRE_PROD_SELF_TEST_OK scenarios=3\n";
        return 0;
    }

    private function assertStepList(): void
    {
        $result = $this->runGate(['--list']);
        if ($result['exitCode'] !== 0) {
            throw new RuntimeException('failed to list local pre-prod gate steps: ' . $this->compactOutput($result['output']));
        }
        $steps = array_values(array_filter(array_map('trim', preg_split('/\R/', $result['output']) ?: [])));
        $missingSteps = array_values(array_diff(self::REQUIRED_STEPS, $steps));
        if ($missingSteps !== []) {
            throw new RuntimeException('local pre-prod gate list is missing steps: ' . implode(',', $missingSteps));
        }
    }

    private function assertPartialRun(): void
    {
        $result = $this->runGate(['--filter=public_runtime', '--skip-live', '--skip-cargo', '--skip-release-self-test']);
        if ($result['exitCode'] !== 0 || !str_contains($result['output'], 'LOCAL_PRE_PROD_PARTIAL_OK')) {
            throw new RuntimeException('partial local pre-prod run did not return partial marker: ' . $this->compactOutput($result['output']));
        }
        if (str_contains($result['output'], 'LOCAL_PRE_PROD_GATE_OK')) {
            throw new RuntimeException('partial local pre-prod run returned full gate marker: ' . $this->compactOutput($result['output']));
        }
    }

    private function assertNoMatchFailure(): void
    {
        $result = $this->runGate(['--filter=no_such_step', '--skip-live', '--skip-cargo', '--skip-release-self-test']);
        if ($result['exitCode'] !== 1 || !str_contains($result['output'], 'LOCAL_PRE_PROD_GATE_NO_MATCH')) {
            throw new RuntimeException('no-match local pre-prod run did not fail with no-match marker: ' . $this->compactOutput($result['output']));
        }
    }

    private function runGate(array $arguments): array
    {
        $process = proc_open(
            array_merge([$this->phpBinary, __DIR__ . DIRECTORY_SEPARATOR . 'localPreProdGate.php'], $arguments),
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $this->projectRoot,
            getenv(),
        );
        if (!is_resource($process)) {
            throw new RuntimeException('proc_open failed');
        }
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        return [
            'exitCode' => proc_close($process),
            'output' => trim((string)$stdout . "\n" . (string)$stderr),
        ];
    }

    private function compactOutput(string $output): string
    {
        $normalized = preg_replace('/\s+/', ' ', trim($output)) ?? '';
        return strlen($normalized) <= 1400 ? $normalized : substr($normalized, 0, 700) . ' ... ' . substr($normalized, -700);
    }
}

try {
    exit((new LocalPreProdGateSelfTest())->run());
} catch (Throwable $exception) {
    fwrite(STDERR, 'LOCAL_PRE_PROD_SELF_TEST_FAILED reason=' . $exception->getMessage() . "\n");
    exit(1);
}
