<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

class TestSecurityHeaders extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:test-headers
                            {url? : URL to test (defaults to APP_URL)}
                            {--live : Make actual HTTP request to test headers}
                            {--config-only : Only check configuration, no HTTP request}
                            {--format=table : Output format (table, json)}
                            {--strict : Use strict security requirements}
                            {--include-csp : Include detailed CSP analysis}
                            {--insecure : Disable SSL certificate verification}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test and validate security headers implementation against best practices';

    /**
     * Required headers with their validation rules.
     *
     * @var array<string, array<string, mixed>>
     */
    protected array $headerRules = [
        'Strict-Transport-Security' => [
            'required' => true,
            'severity' => 'high',
            'recommended' => 'max-age=31536000; includeSubDomains',
            'validate' => 'validateHsts',
        ],
        'X-Frame-Options' => [
            'required' => true,
            'severity' => 'high',
            'recommended' => 'SAMEORIGIN',
            'validate' => 'validateXFrameOptions',
        ],
        'X-Content-Type-Options' => [
            'required' => true,
            'severity' => 'medium',
            'recommended' => 'nosniff',
            'validate' => 'validateXContentTypeOptions',
        ],
        'Content-Security-Policy' => [
            'required' => true,
            'severity' => 'high',
            'recommended' => null,
            'validate' => 'validateCsp',
        ],
        'X-XSS-Protection' => [
            'required' => false,
            'severity' => 'low',
            'recommended' => '1; mode=block',
            'validate' => 'validateXssProtection',
        ],
        'Referrer-Policy' => [
            'required' => false,
            'severity' => 'medium',
            'recommended' => 'strict-origin-when-cross-origin',
            'validate' => 'validateReferrerPolicy',
        ],
        'Permissions-Policy' => [
            'required' => false,
            'severity' => 'medium',
            'recommended' => null,
            'validate' => 'validatePermissionsPolicy',
        ],
        'Cross-Origin-Opener-Policy' => [
            'required' => false,
            'severity' => 'medium',
            'recommended' => 'same-origin',
            'validate' => 'validateCoop',
        ],
        'Cross-Origin-Resource-Policy' => [
            'required' => false,
            'severity' => 'medium',
            'recommended' => 'same-origin',
            'validate' => 'validateCorp',
        ],
        'Cross-Origin-Embedder-Policy' => [
            'required' => false,
            'severity' => 'low',
            'recommended' => 'require-corp',
            'validate' => 'validateCoep',
        ],
    ];

    /**
     * Validation results.
     *
     * @var array<string, array<string, mixed>>
     */
    protected array $results = [];

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('Security Headers Analysis');
        $this->newLine();

        $url = $this->argument('url') ?? config('app.url');

        if ($this->option('strict')) {
            $this->enableStrictMode();
        }

        // Analyze configuration
        if (! $this->option('live') || $this->option('config-only')) {
            $this->info('Configuration Analysis:');
            $this->analyzeConfiguration();
        }

        // Live test
        if ($this->option('live') && ! $this->option('config-only')) {
            $this->newLine();
            $this->info("Live Test: {$url}");
            $this->performLiveTest($url);
        }

        // Output results
        $format = $this->option('format');
        if ($format === 'json') {
            $this->outputJson();
        } else {
            $this->outputTable();
        }

        // CSP analysis
        if ($this->option('include-csp')) {
            $this->analyzeCsp();
        }

        // Display grade and recommendations
        $this->displayGradeAndRecommendations();

        return $this->determineExitCode();
    }

    /**
     * Enable strict mode (more headers required).
     */
    protected function enableStrictMode(): void
    {
        foreach ($this->headerRules as $header => &$rules) {
            if (in_array($header, ['Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy'])) {
                $rules['required'] = true;
            }
        }
    }

    /**
     * Analyze security configuration.
     */
    protected function analyzeConfiguration(): void
    {
        $configuredHeaders = config('artisanpack.security.security-headers', []);

        foreach ($this->headerRules as $header => $rules) {
            $value = $configuredHeaders[$header] ?? null;
            $this->validateHeader($header, $value, 'config');
        }
    }

    /**
     * Perform live HTTP test.
     */
    protected function performLiveTest(string $url): void
    {
        try {
            // Determine if SSL verification should be disabled
            $verifySsl = $this->shouldVerifySsl($url);

            if (! $verifySsl) {
                $this->warn('SSL certificate verification is disabled for this request.');
            }

            $response = Http::withOptions([
                'verify' => $verifySsl,
                'timeout' => 10,
            ])->get($url);

            $headers = $response->headers();

            foreach ($this->headerRules as $header => $rules) {
                $value = $headers[$header][0] ?? null;
                $this->validateHeader($header, $value, 'live');
            }
        } catch (\Exception $e) {
            $this->error("Failed to fetch URL: {$e->getMessage()}");
            $this->warn('Live test skipped. Results show configuration analysis only.');
        }
    }

    /**
     * Determine if SSL verification should be enabled.
     */
    protected function shouldVerifySsl(string $url): bool
    {
        // If --insecure is explicitly passed, disable verification
        if ($this->option('insecure')) {
            return false;
        }

        // Check if URL is localhost or loopback
        $parsedUrl = parse_url($url);
        $host = $parsedUrl['host'] ?? '';

        $localHosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0'];

        if (in_array($host, $localHosts, true) || str_ends_with($host, '.localhost')) {
            return false;
        }

        // Default: verify SSL
        return true;
    }

    /**
     * Validate a single header.
     */
    protected function validateHeader(string $header, ?string $value, string $source): void
    {
        $rules = $this->headerRules[$header];
        $validationMethod = $rules['validate'];

        $result = [
            'header' => $header,
            'value' => $value,
            'source' => $source,
            'present' => $value !== null && $value !== '',
            'required' => $rules['required'],
            'severity' => $rules['severity'],
            'status' => 'unknown',
            'grade' => 'F',
            'message' => '',
        ];

        if (! $result['present']) {
            $result['status'] = $rules['required'] ? 'missing' : 'optional_missing';
            $result['grade'] = $rules['required'] ? 'F' : 'D';
            $result['message'] = $rules['required'] ? 'Required header missing' : 'Recommended header not configured';
        } else {
            // Run specific validation
            $validation = $this->$validationMethod($value);
            $result = array_merge($result, $validation);
        }

        $key = "{$header}_{$source}";
        $this->results[$key] = $result;
    }

    /**
     * Validate HSTS header.
     *
     * @return array<string, mixed>
     */
    protected function validateHsts(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'missing', 'grade' => 'F', 'message' => 'HSTS not configured'];
        }

        $result = ['status' => 'pass', 'grade' => 'A', 'message' => ''];

        // Check max-age
        if (preg_match('/max-age=(\d+)/', $value, $matches)) {
            $maxAge = (int) $matches[1];
            if ($maxAge < 31536000) { // Less than 1 year
                $result['grade'] = 'B';
                $result['message'] = 'max-age should be at least 31536000 (1 year)';
            }
            if ($maxAge < 86400) { // Less than 1 day
                $result['grade'] = 'C';
                $result['message'] = 'max-age is too short';
            }
        } else {
            $result['grade'] = 'D';
            $result['message'] = 'max-age directive missing';
        }

        // Check for includeSubDomains
        if (! str_contains(strtolower($value), 'includesubdomains')) {
            if ($result['grade'] === 'A') {
                $result['grade'] = 'B';
            }
            $result['message'] = trim($result['message'].' Consider adding includeSubDomains');
        }

        // Check for preload
        if (str_contains(strtolower($value), 'preload')) {
            $result['message'] = trim($result['message'].' (preload enabled)');
        }

        return $result;
    }

    /**
     * Validate X-Frame-Options header.
     *
     * @return array<string, mixed>
     */
    protected function validateXFrameOptions(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'missing', 'grade' => 'F', 'message' => 'X-Frame-Options not configured'];
        }

        $value = strtoupper(trim($value));

        if ($value === 'DENY') {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Blocks all framing'];
        }

        if ($value === 'SAMEORIGIN') {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Allows same-origin framing'];
        }

        if (str_starts_with($value, 'ALLOW-FROM')) {
            return ['status' => 'warn', 'grade' => 'C', 'message' => 'ALLOW-FROM is deprecated'];
        }

        return ['status' => 'fail', 'grade' => 'D', 'message' => 'Invalid value'];
    }

    /**
     * Validate X-Content-Type-Options header.
     *
     * @return array<string, mixed>
     */
    protected function validateXContentTypeOptions(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'missing', 'grade' => 'F', 'message' => 'X-Content-Type-Options not configured'];
        }

        if (strtolower(trim($value)) === 'nosniff') {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Prevents MIME type sniffing'];
        }

        return ['status' => 'fail', 'grade' => 'D', 'message' => "Invalid value: should be 'nosniff'"];
    }

    /**
     * Validate Content-Security-Policy header.
     *
     * @return array<string, mixed>
     */
    protected function validateCsp(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'missing', 'grade' => 'F', 'message' => 'CSP not configured'];
        }

        $result = ['status' => 'pass', 'grade' => 'A', 'message' => ''];
        $issues = [];

        // Check for unsafe-inline
        if (str_contains($value, "'unsafe-inline'") && ! str_contains($value, "'strict-dynamic'")) {
            $hasNonce = (bool) preg_match("/'nonce-/", $value);
            if (! $hasNonce) {
                $issues[] = "uses 'unsafe-inline'";
                $result['grade'] = 'C';
            }
        }

        // Check for unsafe-eval
        if (str_contains($value, "'unsafe-eval'")) {
            $issues[] = "uses 'unsafe-eval'";
            if ($result['grade'] < 'C') {
                $result['grade'] = 'C';
            }
        }

        // Check for wildcards
        if (preg_match('/\s\*\s|^\*\s|\s\*$/', $value)) {
            $issues[] = 'contains wildcard (*)';
            $result['grade'] = 'D';
        }

        // Check for default-src
        if (! str_contains($value, 'default-src')) {
            $issues[] = 'missing default-src';
            if ($result['grade'] < 'B') {
                $result['grade'] = 'B';
            }
        }

        if (! empty($issues)) {
            $result['message'] = implode(', ', $issues);
            $result['status'] = 'warn';
        } else {
            $result['message'] = 'Well-configured policy';
        }

        return $result;
    }

    /**
     * Validate X-XSS-Protection header.
     *
     * @return array<string, mixed>
     */
    protected function validateXssProtection(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'optional_missing', 'grade' => 'B', 'message' => 'Legacy header, CSP preferred'];
        }

        $value = strtolower(trim($value));

        if ($value === '0') {
            return ['status' => 'pass', 'grade' => 'B', 'message' => 'Disabled (recommended if CSP is used)'];
        }

        if ($value === '1; mode=block') {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Enabled with block mode'];
        }

        if ($value === '1') {
            return ['status' => 'warn', 'grade' => 'B', 'message' => 'Consider adding mode=block'];
        }

        return ['status' => 'warn', 'grade' => 'C', 'message' => 'Unexpected value'];
    }

    /**
     * Validate Referrer-Policy header.
     *
     * @return array<string, mixed>
     */
    protected function validateReferrerPolicy(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'optional_missing', 'grade' => 'C', 'message' => 'Referrer-Policy not configured'];
        }

        $strictPolicies = [
            'no-referrer',
            'no-referrer-when-downgrade',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'same-origin',
        ];

        $value = strtolower(trim($value));

        if (in_array($value, $strictPolicies, true)) {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Secure referrer policy'];
        }

        if ($value === 'origin' || $value === 'origin-when-cross-origin') {
            return ['status' => 'warn', 'grade' => 'B', 'message' => 'Consider stricter policy'];
        }

        if ($value === 'unsafe-url') {
            return ['status' => 'fail', 'grade' => 'D', 'message' => 'Unsafe: exposes full URL'];
        }

        return ['status' => 'warn', 'grade' => 'C', 'message' => 'Unknown policy'];
    }

    /**
     * Validate Permissions-Policy header.
     *
     * @return array<string, mixed>
     */
    protected function validatePermissionsPolicy(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'optional_missing', 'grade' => 'C', 'message' => 'Permissions-Policy not configured'];
        }

        // Check if it restricts sensitive features
        $sensitiveFeatures = ['camera', 'microphone', 'geolocation', 'payment'];
        $restrictedCount = 0;

        foreach ($sensitiveFeatures as $feature) {
            if (str_contains($value, "{$feature}=()") || str_contains($value, "{$feature}=self")) {
                $restrictedCount++;
            }
        }

        if ($restrictedCount >= 3) {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Restricts sensitive features'];
        }

        if ($restrictedCount >= 1) {
            return ['status' => 'pass', 'grade' => 'B', 'message' => 'Some features restricted'];
        }

        return ['status' => 'warn', 'grade' => 'C', 'message' => 'Consider restricting more features'];
    }

    /**
     * Validate Cross-Origin-Opener-Policy header.
     *
     * @return array<string, mixed>
     */
    protected function validateCoop(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'optional_missing', 'grade' => 'C', 'message' => 'COOP not configured'];
        }

        $value = strtolower(trim($value));

        if ($value === 'same-origin') {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Maximum isolation'];
        }

        if ($value === 'same-origin-allow-popups') {
            return ['status' => 'pass', 'grade' => 'B', 'message' => 'Allows popups from same origin'];
        }

        if ($value === 'unsafe-none') {
            return ['status' => 'warn', 'grade' => 'D', 'message' => 'No protection'];
        }

        return ['status' => 'warn', 'grade' => 'C', 'message' => 'Unknown value'];
    }

    /**
     * Validate Cross-Origin-Resource-Policy header.
     *
     * @return array<string, mixed>
     */
    protected function validateCorp(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'optional_missing', 'grade' => 'C', 'message' => 'CORP not configured'];
        }

        $value = strtolower(trim($value));

        if ($value === 'same-origin') {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Strict same-origin policy'];
        }

        if ($value === 'same-site') {
            return ['status' => 'pass', 'grade' => 'B', 'message' => 'Same-site policy'];
        }

        if ($value === 'cross-origin') {
            return ['status' => 'warn', 'grade' => 'C', 'message' => 'Allows cross-origin access'];
        }

        return ['status' => 'warn', 'grade' => 'C', 'message' => 'Unknown value'];
    }

    /**
     * Validate Cross-Origin-Embedder-Policy header.
     *
     * @return array<string, mixed>
     */
    protected function validateCoep(?string $value): array
    {
        if (empty($value)) {
            return ['status' => 'optional_missing', 'grade' => 'C', 'message' => 'COEP not configured'];
        }

        $value = strtolower(trim($value));

        if ($value === 'require-corp') {
            return ['status' => 'pass', 'grade' => 'A', 'message' => 'Requires CORP for subresources'];
        }

        if ($value === 'credentialless') {
            return ['status' => 'pass', 'grade' => 'B', 'message' => 'Removes credentials from cross-origin requests'];
        }

        if ($value === 'unsafe-none') {
            return ['status' => 'warn', 'grade' => 'D', 'message' => 'No protection'];
        }

        return ['status' => 'warn', 'grade' => 'C', 'message' => 'Unknown value'];
    }

    /**
     * Output results as table.
     */
    protected function outputTable(): void
    {
        $this->newLine();

        $rows = [];
        $processedHeaders = [];

        foreach ($this->results as $result) {
            $header = $result['header'];
            if (in_array($header, $processedHeaders, true)) {
                continue; // Show each header only once
            }
            $processedHeaders[] = $header;

            $statusIcon = match ($result['status']) {
                'pass' => '<fg=green>PASS</>',
                'warn' => '<fg=yellow>WARN</>',
                'missing' => '<fg=red>MISS</>',
                'optional_missing' => '<fg=gray>N/A</>',
                default => '<fg=gray>UNKN</>',
            };

            $gradeColor = match ($result['grade']) {
                'A' => 'green',
                'B' => 'cyan',
                'C' => 'yellow',
                'D' => 'red',
                'F' => 'red',
                default => 'gray',
            };

            $value = $result['value'] ?? '';
            if (strlen($value) > 40) {
                $value = substr($value, 0, 37).'...';
            }

            $rows[] = [
                $header,
                $statusIcon,
                $value ?: '<fg=gray>(not set)</>',
                "<fg={$gradeColor}>{$result['grade']}</>",
            ];
        }

        $this->table(['Header', 'Status', 'Value', 'Grade'], $rows);
    }

    /**
     * Output results as JSON.
     */
    protected function outputJson(): void
    {
        $output = [
            'scan_date' => now()->toIso8601String(),
            'overall_grade' => $this->calculateOverallGrade(),
            'results' => array_values($this->results),
            'recommendations' => $this->getRecommendations(),
        ];

        $this->line(json_encode($output, JSON_PRETTY_PRINT));
    }

    /**
     * Analyze CSP in detail.
     */
    protected function analyzeCsp(): void
    {
        $this->newLine();
        $this->info('Detailed CSP Analysis:');
        $this->newLine();

        // Find CSP from results
        $cspValue = null;
        foreach ($this->results as $result) {
            if ($result['header'] === 'Content-Security-Policy' && ! empty($result['value'])) {
                $cspValue = $result['value'];
                break;
            }
        }

        if (! $cspValue) {
            $this->warn('No CSP found to analyze.');

            return;
        }

        // Parse directives
        $directives = [];
        $parts = explode(';', $cspValue);

        foreach ($parts as $part) {
            $part = trim($part);
            if (empty($part)) {
                continue;
            }

            $tokens = preg_split('/\s+/', $part);
            $directive = array_shift($tokens);
            $directives[$directive] = $tokens;
        }

        $rows = [];
        foreach ($directives as $directive => $values) {
            $status = $this->analyzeCspDirective($directive, $values);
            $valuesStr = implode(' ', array_slice($values, 0, 3));
            if (count($values) > 3) {
                $valuesStr .= ' (+' . (count($values) - 3) . ')';
            }
            $rows[] = [$directive, $valuesStr, $status];
        }

        $this->table(['Directive', 'Values', 'Assessment'], $rows);
    }

    /**
     * Analyze a CSP directive.
     *
     * @param  array<string>  $values
     */
    protected function analyzeCspDirective(string $directive, array $values): string
    {
        // Check for unsafe practices
        if (in_array("'unsafe-inline'", $values, true) && ! in_array("'strict-dynamic'", $values, true)) {
            return '<fg=red>Unsafe (inline)</>';
        }

        if (in_array("'unsafe-eval'", $values, true)) {
            return '<fg=red>Unsafe (eval)</>';
        }

        if (in_array('*', $values, true)) {
            return '<fg=yellow>Permissive (*)</>';
        }

        if (in_array("'none'", $values, true)) {
            return '<fg=green>Blocked</>';
        }

        // Check for nonce
        foreach ($values as $value) {
            if (str_starts_with($value, "'nonce-")) {
                return '<fg=green>Nonce-based</>';
            }
        }

        if (in_array("'strict-dynamic'", $values, true)) {
            return '<fg=green>Strict Dynamic</>';
        }

        if (count($values) === 1 && $values[0] === "'self'") {
            return '<fg=green>Self only</>';
        }

        return '<fg=blue>Configured</>';
    }

    /**
     * Calculate overall grade.
     */
    protected function calculateOverallGrade(): string
    {
        $grades = ['A' => 0, 'B' => 0, 'C' => 0, 'D' => 0, 'F' => 0];
        $weights = ['A' => 4, 'B' => 3, 'C' => 2, 'D' => 1, 'F' => 0];
        $requiredFailures = 0;

        $processedHeaders = [];
        foreach ($this->results as $result) {
            if (in_array($result['header'], $processedHeaders, true)) {
                continue;
            }
            $processedHeaders[] = $result['header'];

            $grade = $result['grade'];
            $grades[$grade]++;

            if ($result['required'] && $grade === 'F') {
                $requiredFailures++;
            }
        }

        // If any required header fails, max grade is C
        if ($requiredFailures > 0) {
            return $requiredFailures > 2 ? 'F' : 'D';
        }

        // Calculate weighted average
        $total = 0;
        $count = 0;
        foreach ($grades as $grade => $num) {
            $total += $weights[$grade] * $num;
            $count += $num;
        }

        if ($count === 0) {
            return 'F';
        }

        $average = $total / $count;

        if ($average >= 3.5) {
            return 'A';
        }
        if ($average >= 2.5) {
            return 'B';
        }
        if ($average >= 1.5) {
            return 'C';
        }
        if ($average >= 0.5) {
            return 'D';
        }

        return 'F';
    }

    /**
     * Get recommendations based on results.
     *
     * @return array<string>
     */
    protected function getRecommendations(): array
    {
        $recommendations = [];
        $processedHeaders = [];

        foreach ($this->results as $result) {
            if (in_array($result['header'], $processedHeaders, true)) {
                continue;
            }
            $processedHeaders[] = $result['header'];

            if ($result['status'] === 'missing' && $result['required']) {
                $recommendations[] = "Add required header: {$result['header']}";
            } elseif ($result['status'] === 'optional_missing') {
                $recommendations[] = "Consider adding: {$result['header']}";
            } elseif (! empty($result['message']) && $result['status'] === 'warn') {
                $recommendations[] = "{$result['header']}: {$result['message']}";
            }
        }

        return $recommendations;
    }

    /**
     * Display grade and recommendations.
     */
    protected function displayGradeAndRecommendations(): void
    {
        $grade = $this->calculateOverallGrade();

        $gradeColor = match ($grade) {
            'A' => 'green',
            'B' => 'cyan',
            'C' => 'yellow',
            'D', 'F' => 'red',
            default => 'gray',
        };

        $this->newLine();
        $this->line("<fg=white;options=bold>Overall Security Headers Grade: </><fg={$gradeColor};options=bold>{$grade}</>");
        $this->newLine();

        $recommendations = $this->getRecommendations();
        if (! empty($recommendations)) {
            $this->info('Recommendations:');
            foreach ($recommendations as $i => $rec) {
                $this->line('  '.($i + 1).". {$rec}");
            }
        } else {
            $this->info('No recommendations - security headers are well configured!');
        }
    }

    /**
     * Determine exit code based on results.
     */
    protected function determineExitCode(): int
    {
        $grade = $this->calculateOverallGrade();

        // Fail if grade is D or F
        if (in_array($grade, ['D', 'F'], true)) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
