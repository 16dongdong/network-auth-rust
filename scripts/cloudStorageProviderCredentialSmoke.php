<?php
declare(strict_types=1);

final class CloudStorageProviderCredentialSmoke
{
    private const providerAliyun = 'aliyun_oss';
    private const providerTencent = 'tencent_cos';

    public function run(): int
    {
        $provider = $this->provider();
        if ($provider === '') {
            echo "CLOUD_PROVIDER_CREDENTIALS_MISSING provider=unset missing=ACE_CLOUD_LIVE_PROVIDER\n";
            echo "LIVE_SMOKE_BLOCKED cloud provider live smoke requires aliyun_oss or tencent_cos credentials\n";
            return 0;
        }
        if (!in_array($provider, [self::providerAliyun, self::providerTencent], true)) {
            fwrite(STDERR, "CLOUD_PROVIDER_UNSUPPORTED provider={$provider}\n");
            return 1;
        }

        $required = $this->requiredVariables($provider);
        $missing = [];
        foreach ($required as $logicalName => $variableNames) {
            if ($this->firstEnv($variableNames) === '') {
                $missing[] = $logicalName . ':' . implode('|', $variableNames);
            }
        }

        if ($missing !== []) {
            echo "CLOUD_PROVIDER_CREDENTIALS_MISSING provider={$provider} missing=" . implode(',', $missing) . "\n";
            echo "LIVE_SMOKE_BLOCKED cloud provider live smoke requires provider credentials in environment variables\n";
            return 0;
        }

        $summary = $this->summary($provider, $required);
        echo "CLOUD_PROVIDER_CREDENTIALS_READY " . http_build_query($summary, '', ' ', PHP_QUERY_RFC3986) . "\n";
        return 0;
    }

    private function provider(): string
    {
        $provider = strtolower($this->env('ACE_CLOUD_LIVE_PROVIDER'));
        if ($provider !== '') {
            return $provider;
        }
        if ($this->hasAnyEnv(['ACE_ALIYUN_OSS_BUCKET', 'ACE_ALIYUN_OSS_ENDPOINT', 'ACE_ALIYUN_OSS_ACCESS_KEY', 'ACE_ALIYUN_OSS_SECRET'])) {
            return self::providerAliyun;
        }
        if ($this->hasAnyEnv(['ACE_TENCENT_COS_BUCKET', 'ACE_TENCENT_COS_REGION', 'ACE_TENCENT_COS_ACCESS_KEY', 'ACE_TENCENT_COS_SECRET'])) {
            return self::providerTencent;
        }
        return '';
    }

    private function requiredVariables(string $provider): array
    {
        return match ($provider) {
            self::providerAliyun => [
                'bucket' => ['ACE_ALIYUN_OSS_BUCKET', 'ACE_CLOUD_LIVE_BUCKET'],
                'endpoint' => ['ACE_ALIYUN_OSS_ENDPOINT', 'ACE_CLOUD_LIVE_ENDPOINT'],
                'access_key' => ['ACE_ALIYUN_OSS_ACCESS_KEY', 'ACE_CLOUD_LIVE_ACCESS_KEY'],
                'secret' => ['ACE_ALIYUN_OSS_SECRET', 'ACE_CLOUD_LIVE_SECRET'],
            ],
            self::providerTencent => [
                'bucket' => ['ACE_TENCENT_COS_BUCKET', 'ACE_CLOUD_LIVE_BUCKET'],
                'region' => ['ACE_TENCENT_COS_REGION', 'ACE_CLOUD_LIVE_REGION'],
                'access_key' => ['ACE_TENCENT_COS_ACCESS_KEY', 'ACE_CLOUD_LIVE_ACCESS_KEY'],
                'secret' => ['ACE_TENCENT_COS_SECRET', 'ACE_CLOUD_LIVE_SECRET'],
            ],
        };
    }

    private function summary(string $provider, array $required): array
    {
        $summary = ['provider' => $provider];
        foreach ($required as $logicalName => $variableNames) {
            if ($logicalName === 'access_key' || $logicalName === 'secret') {
                $summary[$logicalName] = 'set';
                continue;
            }
            $summary[$logicalName] = $this->firstEnv($variableNames);
        }
        return $summary;
    }

    private function hasAnyEnv(array $names): bool
    {
        foreach ($names as $name) {
            if ($this->env($name) !== '') {
                return true;
            }
        }
        return false;
    }

    private function firstEnv(array $names): string
    {
        foreach ($names as $name) {
            $value = $this->env($name);
            if ($value !== '') {
                return $value;
            }
        }
        return '';
    }

    private function env(string $name): string
    {
        $value = getenv($name);
        return is_string($value) ? trim($value) : '';
    }
}

$smoke = new CloudStorageProviderCredentialSmoke();
exit($smoke->run());
