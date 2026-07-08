<?php
declare(strict_types=1);

final class ProdCutoverSequenceGate
{
    private const REQUIRED_PRE_PROD_STEPS = [
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

    public function run(array $arguments): int
    {
        if (in_array('--help', $arguments, true) || in_array('-h', $arguments, true)) {
            $this->printHelp();
            return 0;
        }

        $mode = in_array('--post-cutover', $arguments, true) ? 'post' : 'pre';
        $checks = $mode === 'pre' ? $this->preCutoverChecks() : $this->postCutoverChecks();
        foreach ($checks as $check) {
            echo $check . "\n";
        }

        echo $mode === 'pre'
            ? "PROD_CUTOVER_SEQUENCE_PRE_OK\n"
            : "PROD_CUTOVER_SEQUENCE_POST_OK\n";
        return 0;
    }

    private function printHelp(): void
    {
        echo "Usage: php scripts/prodCutoverSequenceGate.php [--pre-cutover|--post-cutover]\n";
        echo "Default pre mode verifies prod is PHP, demo is Rust, and the local gate includes all required steps.\n";
        echo "Post mode verifies prod and demo public runtimes are both Rust after production cutover.\n";
    }

    private function preCutoverChecks(): array
    {
        $lines = [];
        $this->assertPreProdStepList();
        $lines[] = 'PROD_CUTOVER_PRE_STEP_OK name=local_pre_prod_step_list';

        $this->runRequired(
            [$this->phpBinary, $this->scriptPath('publicRuntimeReadinessGate.php'), '--expect-runtime=prod:php', '--expect-runtime=demo:rust'],
            'PUBLIC_RUNTIME_READINESS_OK',
            'prod/demo public pre-cutover runtime',
        );
        $lines[] = 'PROD_CUTOVER_PRE_STEP_OK name=public_runtime_prod_php_demo_rust';

        $postGate = $this->runCommand([
            $this->phpBinary,
            $this->scriptPath('publicRuntimeReadinessGate.php'),
            '--expect-runtime=prod:rust',
            '--expect-runtime=demo:rust',
        ]);
        if ($postGate['exitCode'] === 0) {
            throw new RuntimeException('post-cutover public runtime gate unexpectedly passed while pre-cutover prod should still be PHP');
        }
        if (!str_contains($postGate['output'], 'PUBLIC_RUNTIME_HEALTH_FAILED target=prod')) {
            throw new RuntimeException('post-cutover public runtime gate failed for an unexpected reason: ' . $this->compactOutput($postGate['output']));
        }
        $lines[] = 'PROD_CUTOVER_PRE_STEP_OK name=post_cutover_public_gate_still_blocks';
        $lines[] = 'PROD_CUTOVER_NEXT_COMMAND php scripts/localPreProdGate.php';
        $lines[] = 'PROD_CUTOVER_NEXT_COMMAND remote pre-cutover-final-gate.sh';
        $lines[] = 'PROD_CUTOVER_NEXT_COMMAND remote switch-release.sh --apply';
        $lines[] = 'PROD_CUTOVER_NEXT_COMMAND remote post-cutover-final-gate.sh';
        $lines[] = 'PROD_CUTOVER_NEXT_COMMAND php scripts/prodCutoverSequenceGate.php --post-cutover';
        return $lines;
    }

    private function postCutoverChecks(): array
    {
        $this->runRequired(
            [$this->phpBinary, $this->scriptPath('publicRuntimeReadinessGate.php'), '--expect-runtime=prod:rust', '--expect-runtime=demo:rust'],
            'PUBLIC_RUNTIME_READINESS_OK',
            'prod/demo public post-cutover runtime',
        );
        return ['PROD_CUTOVER_POST_STEP_OK name=public_runtime_prod_rust_demo_rust'];
    }

    private function assertPreProdStepList(): void
    {
        $result = $this->runCommand([$this->phpBinary, $this->scriptPath('localPreProdGate.php'), '--list']);
        if ($result['exitCode'] !== 0) {
            throw new RuntimeException('failed to list local pre-prod gate steps: ' . $this->compactOutput($result['output']));
        }
        $actualSteps = array_values(array_filter(array_map('trim', preg_split('/\R/', $result['output']) ?: [])));
        $missingSteps = array_values(array_diff(self::REQUIRED_PRE_PROD_STEPS, $actualSteps));
        if ($missingSteps !== []) {
            throw new RuntimeException('local pre-prod gate is missing required steps: ' . implode(',', $missingSteps));
        }
    }

    private function runRequired(array $command, string $marker, string $label): void
    {
        $result = $this->runCommand($command);
        if ($result['exitCode'] === 0 && str_contains($result['output'], $marker)) {
            return;
        }
        throw new RuntimeException("{$label} failed: " . $this->compactOutput($result['output']));
    }

    private function runCommand(array $command): array
    {
        $process = proc_open(
            $command,
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

    private function scriptPath(string $scriptName): string
    {
        return __DIR__ . DIRECTORY_SEPARATOR . $scriptName;
    }

    private function compactOutput(string $output): string
    {
        $normalized = preg_replace('/\s+/', ' ', trim($output)) ?? '';
        return strlen($normalized) <= 1400 ? $normalized : substr($normalized, 0, 700) . ' ... ' . substr($normalized, -700);
    }
}

try {
    exit((new ProdCutoverSequenceGate())->run(array_slice($_SERVER['argv'] ?? [], 1)));
} catch (Throwable $exception) {
    fwrite(STDERR, 'PROD_CUTOVER_SEQUENCE_FAILED reason=' . $exception->getMessage() . "\n");
    exit(1);
}
