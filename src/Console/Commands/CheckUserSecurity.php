<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\AccountLockout;
use ArtisanPackUI\Security\Models\ApiToken;
use ArtisanPackUI\Security\Models\SecurityEvent;
use ArtisanPackUI\Security\Models\SuspiciousActivity;
use ArtisanPackUI\Security\Models\UserDevice;
use ArtisanPackUI\Security\Models\UserSession;
use ArtisanPackUI\Security\Services\PasswordSecurityService;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;

class CheckUserSecurity extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:user-security
                            {user? : Specific user ID or email to check}
                            {--all : Check all users (may be slow)}
                            {--issues-only : Only show users with security issues}
                            {--format=table : Output format (table, json)}
                            {--export= : Export results to file}
                            {--check= : Specific checks to run (comma-separated: password,2fa,sessions,lockouts,suspicious,tokens)}
                            {--limit=100 : Limit number of users to check}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check and report on user account security status';

    /**
     * Password security service.
     */
    protected ?PasswordSecurityService $passwordService = null;

    /**
     * User model class.
     */
    protected string $userModel;

    /**
     * Available security checks.
     *
     * @var array<string>
     */
    protected array $availableChecks = [
        'password',
        '2fa',
        'sessions',
        'lockouts',
        'suspicious',
        'tokens',
    ];

    /**
     * Execute the console command.
     */
    public function handle(PasswordSecurityService $passwordService): int
    {
        $this->passwordService = $passwordService;
        $this->userModel = config('auth.providers.users.model', 'App\\Models\\User');

        $this->info('User Security Analysis');
        $this->newLine();

        // Check if user model exists
        if (! class_exists($this->userModel)) {
            $this->error("User model not found: {$this->userModel}");

            return self::FAILURE;
        }

        // Single user check
        if ($userId = $this->argument('user')) {
            return $this->checkSingleUser($userId);
        }

        // All users check
        if ($this->option('all')) {
            return $this->checkAllUsers();
        }

        // Default: show summary statistics
        return $this->showSecuritySummary();
    }

    /**
     * Check security for a single user.
     */
    protected function checkSingleUser(string $identifier): int
    {
        $user = $this->findUser($identifier);

        if (! $user) {
            $this->error("User not found: {$identifier}");

            return self::FAILURE;
        }

        $issues = $this->runSecurityChecks($user);

        if ($this->option('format') === 'json') {
            $this->outputUserJson($user, $issues);
        } else {
            $this->displayUserReport($user, $issues);
        }

        // Export if requested
        if ($exportPath = $this->option('export')) {
            $this->exportResults([$user->getKey() => $issues], $exportPath);
        }

        return $issues->where('severity', 'high')->count() > 0 ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Check security for all users.
     */
    protected function checkAllUsers(): int
    {
        $limit = (int) $this->option('limit');
        $issuesOnly = $this->option('issues-only');

        $userClass = $this->userModel;
        $query = $userClass::query();

        $total = $query->count();
        $this->info("Checking {$total} users (limit: {$limit})...");

        $results = [];
        $usersWithIssues = 0;
        $allIssues = collect();

        $bar = $this->output->createProgressBar(min($total, $limit));
        $bar->start();

        $query->take($limit)->chunk(100, function ($users) use (&$results, &$usersWithIssues, &$allIssues, $issuesOnly, $bar) {
            foreach ($users as $user) {
                $issues = $this->runSecurityChecks($user);

                if ($issues->count() > 0) {
                    $usersWithIssues++;
                    $allIssues = $allIssues->merge($issues);
                }

                if (! $issuesOnly || $issues->count() > 0) {
                    $results[$user->getKey()] = [
                        'user' => $user,
                        'issues' => $issues,
                    ];
                }

                $bar->advance();
            }
        });

        $bar->finish();
        $this->newLine(2);

        // Display results
        if ($this->option('format') === 'json') {
            $this->outputAllUsersJson($results);
        } else {
            $this->displayAllUsersReport($results, $usersWithIssues, $allIssues);
        }

        // Export if requested
        if ($exportPath = $this->option('export')) {
            $exportData = [];
            foreach ($results as $userId => $data) {
                $exportData[$userId] = $data['issues'];
            }
            $this->exportResults($exportData, $exportPath);
        }

        return self::SUCCESS;
    }

    /**
     * Show security summary statistics.
     */
    protected function showSecuritySummary(): int
    {
        $userClass = $this->userModel;
        $userTable = (new $userClass)->getTable();

        $stats = [
            'total_users' => $userClass::count(),
        ];

        // Check 2FA status if possible
        if ($this->hasColumn($userTable, 'two_factor_secret') || $this->hasColumn($userTable, 'two_factor_enabled')) {
            $twoFactorColumn = $this->hasColumn($userTable, 'two_factor_enabled') ? 'two_factor_enabled' : 'two_factor_secret';
            $stats['without_2fa'] = $userClass::whereNull($twoFactorColumn)->count();
        } else {
            $stats['without_2fa'] = 'N/A (column not found)';
        }

        // Check password age if possible
        if ($this->hasColumn($userTable, 'password_changed_at')) {
            $stats['old_passwords'] = $userClass::where('password_changed_at', '<', now()->subDays(90))->count();
        } else {
            $stats['old_passwords'] = 'N/A';
        }

        // Account lockouts
        if (Schema::hasTable('account_lockouts')) {
            $stats['locked_accounts'] = AccountLockout::active()->distinct('user_id')->count('user_id');
        } else {
            $stats['locked_accounts'] = 'N/A';
        }

        // Suspicious activity
        if (Schema::hasTable('suspicious_activities')) {
            $stats['suspicious_activity'] = SuspiciousActivity::unresolved()->distinct('user_id')->count('user_id');
        } else {
            $stats['suspicious_activity'] = 'N/A';
        }

        // API tokens
        if (Schema::hasTable('personal_access_tokens')) {
            $stats['expiring_tokens_7d'] = ApiToken::where('expires_at', '<=', now()->addDays(7))
                ->where('expires_at', '>', now())
                ->count();
            $stats['never_expiring_tokens'] = ApiToken::whereNull('expires_at')->count();
        } else {
            $stats['expiring_tokens_7d'] = 'N/A';
            $stats['never_expiring_tokens'] = 'N/A';
        }

        // Active sessions
        if (Schema::hasTable('user_sessions')) {
            $stats['active_sessions'] = UserSession::active()->count();
            $stats['users_multiple_sessions'] = UserSession::active()
                ->select('user_id')
                ->groupBy('user_id')
                ->havingRaw('COUNT(*) > 3')
                ->count();
        } else {
            $stats['active_sessions'] = 'N/A';
            $stats['users_multiple_sessions'] = 'N/A';
        }

        // Security events in last 24h
        if (Schema::hasTable('security_events')) {
            $stats['security_events_24h'] = SecurityEvent::where('created_at', '>=', now()->subDay())->count();
            $stats['failed_logins_24h'] = SecurityEvent::where('created_at', '>=', now()->subDay())
                ->where('type', 'authentication')
                ->whereIn('severity', ['warning', 'error', 'critical', 'high'])
                ->count();
        } else {
            $stats['security_events_24h'] = 'N/A';
            $stats['failed_logins_24h'] = 'N/A';
        }

        if ($this->option('format') === 'json') {
            $this->line(json_encode($stats, JSON_PRETTY_PRINT));
        } else {
            $this->displaySummaryTable($stats);
        }

        // Export if requested
        if ($exportPath = $this->option('export')) {
            File::put($exportPath, json_encode($stats, JSON_PRETTY_PRINT));
            $this->info("Summary exported to: {$exportPath}");
        }

        return self::SUCCESS;
    }

    /**
     * Find a user by ID or email.
     */
    protected function findUser(string $identifier): ?Model
    {
        $userClass = $this->userModel;

        // Try by ID first
        if (is_numeric($identifier)) {
            $user = $userClass::find($identifier);
            if ($user) {
                return $user;
            }
        }

        // Try by email
        return $userClass::where('email', $identifier)->first();
    }

    /**
     * Run all security checks for a user.
     *
     * @return Collection<int, array<string, mixed>>
     */
    protected function runSecurityChecks(Model $user): Collection
    {
        $issues = collect();
        $checksToRun = $this->getChecksToRun();

        if (in_array('password', $checksToRun, true)) {
            $issues = $issues->merge($this->checkPasswordSecurity($user));
        }

        if (in_array('2fa', $checksToRun, true)) {
            $issues = $issues->merge($this->check2FAStatus($user));
        }

        if (in_array('sessions', $checksToRun, true)) {
            $issues = $issues->merge($this->checkSessionSecurity($user));
        }

        if (in_array('lockouts', $checksToRun, true)) {
            $issues = $issues->merge($this->checkLockoutStatus($user));
        }

        if (in_array('suspicious', $checksToRun, true)) {
            $issues = $issues->merge($this->checkSuspiciousActivity($user));
        }

        if (in_array('tokens', $checksToRun, true)) {
            $issues = $issues->merge($this->checkApiTokenSecurity($user));
        }

        return $issues;
    }

    /**
     * Get checks to run based on options.
     *
     * @return array<string>
     */
    protected function getChecksToRun(): array
    {
        if ($checks = $this->option('check')) {
            $requested = explode(',', $checks);

            return array_intersect($requested, $this->availableChecks);
        }

        return $this->availableChecks;
    }

    /**
     * Check password security for a user.
     *
     * @return Collection<int, array<string, mixed>>
     */
    protected function checkPasswordSecurity(Model $user): Collection
    {
        $issues = collect();
        $userTable = $user->getTable();

        // Check password age
        if ($this->hasColumn($userTable, 'password_changed_at')) {
            $passwordChangedAt = $user->password_changed_at;
            if ($passwordChangedAt) {
                $daysOld = now()->diffInDays($passwordChangedAt);
                $maxAge = config('artisanpack.security.commands.user_security.password_max_age_days', 90);

                if ($daysOld > $maxAge) {
                    $issues->push([
                        'type' => 'password',
                        'severity' => 'medium',
                        'title' => 'Password is too old',
                        'description' => "Password is {$daysOld} days old (max: {$maxAge} days)",
                        'recommendation' => 'Request password change',
                    ]);
                } elseif ($daysOld > $maxAge - 7) {
                    $issues->push([
                        'type' => 'password',
                        'severity' => 'low',
                        'title' => 'Password expiring soon',
                        'description' => "Password is {$daysOld} days old, expires in ".($maxAge - $daysOld).' days',
                        'recommendation' => 'Consider prompting for password change',
                    ]);
                }
            }
        }

        return $issues;
    }

    /**
     * Check 2FA status for a user.
     *
     * @return Collection<int, array<string, mixed>>
     */
    protected function check2FAStatus(Model $user): Collection
    {
        $issues = collect();
        $userTable = $user->getTable();

        // Check if 2FA columns exist
        $has2FAColumn = $this->hasColumn($userTable, 'two_factor_secret')
            || $this->hasColumn($userTable, 'two_factor_enabled');

        if (! $has2FAColumn) {
            return $issues;
        }

        $twoFactorEnabled = false;

        if ($this->hasColumn($userTable, 'two_factor_enabled')) {
            $twoFactorEnabled = (bool) $user->two_factor_enabled;
        } elseif ($this->hasColumn($userTable, 'two_factor_secret')) {
            $twoFactorEnabled = ! empty($user->two_factor_secret);
        }

        if (! $twoFactorEnabled) {
            $issues->push([
                'type' => '2fa',
                'severity' => 'medium',
                'title' => 'Two-Factor Authentication not enabled',
                'description' => 'Account does not have 2FA configured',
                'recommendation' => 'Enable 2FA for enhanced security',
            ]);
        }

        return $issues;
    }

    /**
     * Check session security for a user.
     *
     * @return Collection<int, array<string, mixed>>
     */
    protected function checkSessionSecurity(Model $user): Collection
    {
        $issues = collect();

        if (! Schema::hasTable('user_sessions')) {
            return $issues;
        }

        $sessions = UserSession::where('user_id', $user->getKey())
            ->active()
            ->get();

        // Check for too many active sessions
        if ($sessions->count() > 5) {
            $issues->push([
                'type' => 'sessions',
                'severity' => 'low',
                'title' => 'Many active sessions',
                'description' => "User has {$sessions->count()} active sessions",
                'recommendation' => 'Consider reviewing and terminating unused sessions',
            ]);
        }

        // Check for sessions from multiple locations
        $locations = $sessions->pluck('location.country')->unique()->filter()->count();
        if ($locations > 3) {
            $issues->push([
                'type' => 'sessions',
                'severity' => 'medium',
                'title' => 'Sessions from multiple countries',
                'description' => "Active sessions from {$locations} different countries",
                'recommendation' => 'Verify all sessions are legitimate',
            ]);
        }

        return $issues;
    }

    /**
     * Check lockout status for a user.
     *
     * @return Collection<int, array<string, mixed>>
     */
    protected function checkLockoutStatus(Model $user): Collection
    {
        $issues = collect();

        if (! Schema::hasTable('account_lockouts')) {
            return $issues;
        }

        // Check active lockouts
        $activeLockout = AccountLockout::forUser($user->getKey())
            ->active()
            ->first();

        if ($activeLockout) {
            $severity = $activeLockout->isPermanent() ? 'high' : 'medium';
            $issues->push([
                'type' => 'lockouts',
                'severity' => $severity,
                'title' => 'Account is currently locked',
                'description' => "Locked since {$activeLockout->locked_at->diffForHumans()} ({$activeLockout->lockout_type})",
                'recommendation' => 'Review lockout reason and consider unlocking if appropriate',
            ]);
        }

        // Check recent lockout history
        $recentLockouts = AccountLockout::forUser($user->getKey())
            ->where('locked_at', '>=', now()->subDays(30))
            ->count();

        if ($recentLockouts > 3) {
            $issues->push([
                'type' => 'lockouts',
                'severity' => 'medium',
                'title' => 'Multiple recent lockouts',
                'description' => "{$recentLockouts} lockouts in the last 30 days",
                'recommendation' => 'Investigate potential brute force attempts or user issues',
            ]);
        }

        return $issues;
    }

    /**
     * Check suspicious activity for a user.
     *
     * @return Collection<int, array<string, mixed>>
     */
    protected function checkSuspiciousActivity(Model $user): Collection
    {
        $issues = collect();

        if (! Schema::hasTable('suspicious_activities')) {
            return $issues;
        }

        $unresolved = SuspiciousActivity::where('user_id', $user->getKey())
            ->unresolved()
            ->get();

        if ($unresolved->isEmpty()) {
            return $issues;
        }

        // Group by severity
        $bySeverity = $unresolved->groupBy('severity');

        foreach ($bySeverity as $severity => $activities) {
            $count = $activities->count();
            $types = $activities->pluck('type')->unique()->map(fn ($t) => str_replace('_', ' ', $t))->implode(', ');

            $issueSeverity = match ($severity) {
                'critical' => 'high',
                'high' => 'high',
                'medium' => 'medium',
                default => 'low',
            };

            $issues->push([
                'type' => 'suspicious',
                'severity' => $issueSeverity,
                'title' => "Unresolved {$severity} suspicious activity",
                'description' => "{$count} unresolved {$severity} activities: {$types}",
                'recommendation' => 'Review and resolve suspicious activity alerts',
            ]);
        }

        return $issues;
    }

    /**
     * Check API token security for a user.
     *
     * @return Collection<int, array<string, mixed>>
     */
    protected function checkApiTokenSecurity(Model $user): Collection
    {
        $issues = collect();

        if (! Schema::hasTable('personal_access_tokens')) {
            return $issues;
        }

        $tokens = ApiToken::where('tokenable_id', $user->getKey())
            ->where('tokenable_type', get_class($user))
            ->get();

        if ($tokens->isEmpty()) {
            return $issues;
        }

        // Check for never-expiring tokens
        $neverExpiring = $tokens->whereNull('expires_at');
        if ($neverExpiring->count() > 0) {
            $names = $neverExpiring->pluck('name')->take(3)->implode(', ');
            $issues->push([
                'type' => 'tokens',
                'severity' => 'medium',
                'title' => 'API tokens without expiration',
                'description' => "{$neverExpiring->count()} token(s) never expire: {$names}",
                'recommendation' => 'Set expiration dates for API tokens',
            ]);
        }

        // Check for expired but not revoked tokens
        $expired = $tokens->filter(fn ($t) => $t->expires_at && $t->expires_at->isPast());
        if ($expired->count() > 5) {
            $issues->push([
                'type' => 'tokens',
                'severity' => 'low',
                'title' => 'Many expired tokens',
                'description' => "{$expired->count()} expired tokens should be cleaned up",
                'recommendation' => 'Remove expired tokens',
            ]);
        }

        // Check for tokens with broad permissions
        $broadTokens = $tokens->filter(function ($token) {
            $abilities = $token->abilities ?? [];

            return in_array('*', $abilities, true);
        });

        if ($broadTokens->count() > 0) {
            $issues->push([
                'type' => 'tokens',
                'severity' => 'medium',
                'title' => 'Tokens with full permissions',
                'description' => "{$broadTokens->count()} token(s) have wildcard (*) permissions",
                'recommendation' => 'Use specific abilities instead of wildcard permissions',
            ]);
        }

        return $issues;
    }

    /**
     * Check if a column exists on a table.
     */
    protected function hasColumn(string $table, string $column): bool
    {
        return Schema::hasColumn($table, $column);
    }

    /**
     * Calculate security score.
     *
     * @param  Collection<int, array<string, mixed>>  $issues
     */
    protected function calculateSecurityScore(Collection $issues): int
    {
        $score = 100;

        foreach ($issues as $issue) {
            $deduction = match ($issue['severity']) {
                'high' => 25,
                'medium' => 15,
                'low' => 5,
                default => 0,
            };
            $score -= $deduction;
        }

        return max(0, $score);
    }

    /**
     * Display user report.
     *
     * @param  Collection<int, array<string, mixed>>  $issues
     */
    protected function displayUserReport(Model $user, Collection $issues): void
    {
        $email = $user->email ?? 'N/A';
        $id = $user->getKey();

        $this->line("<fg=white;options=bold>User Security Report: {$email} (ID: {$id})</>");
        $this->line(str_repeat('=', 50));
        $this->newLine();

        // Account status
        $this->info('Account Status');
        $this->line(str_repeat('-', 20));
        $this->line(" Created: ".($user->created_at ?? 'Unknown'));
        if (isset($user->last_login_at)) {
            $this->line(' Last Login: '.$user->last_login_at);
        }
        $this->newLine();

        // Security score
        $score = $this->calculateSecurityScore($issues);
        $scoreLabel = match (true) {
            $score >= 90 => '<fg=green>Excellent</>',
            $score >= 70 => '<fg=cyan>Good</>',
            $score >= 50 => '<fg=yellow>Fair</>',
            default => '<fg=red>Needs Attention</>',
        };
        $this->line("<fg=white;options=bold>Security Score:</> {$score}/100 ({$scoreLabel})");
        $this->newLine();

        // Issues
        if ($issues->isEmpty()) {
            $this->info('No security issues found!');
        } else {
            $this->line("<fg=white;options=bold>Issues Found: {$issues->count()}</>");
            $this->line(str_repeat('-', 20));
            $this->newLine();

            foreach ($issues as $issue) {
                $severityColor = match ($issue['severity']) {
                    'high' => 'red',
                    'medium' => 'yellow',
                    'low' => 'cyan',
                    default => 'gray',
                };

                $this->line(" <fg={$severityColor}>[".strtoupper($issue['severity'])."]</> {$issue['title']}");
                $this->line("   {$issue['description']}");
                $this->line("   <fg=blue>Recommendation:</> {$issue['recommendation']}");
                $this->newLine();
            }
        }

        // Sessions summary
        if (Schema::hasTable('user_sessions')) {
            $sessions = UserSession::where('user_id', $user->getKey())->active()->get();
            if ($sessions->count() > 0) {
                $this->info("Sessions ({$sessions->count()} active)");
                $this->line(str_repeat('-', 20));
                foreach ($sessions->take(5) as $session) {
                    $ua = $session->getParsedUserAgent();
                    $browser = $ua['browser'] ?? 'Unknown';
                    $os = $ua['os'] ?? 'Unknown';
                    $location = $session->getLocationDisplay();
                    $current = $session->is_current ? ' (current)' : '';
                    $this->line(" * {$browser}/{$os} - {$location}{$current}");
                }
                if ($sessions->count() > 5) {
                    $this->line(" ... and ".($sessions->count() - 5).' more');
                }
                $this->newLine();
            }
        }

        // Recent events
        if (Schema::hasTable('security_events')) {
            $events = SecurityEvent::where('user_id', $user->getKey())
                ->where('created_at', '>=', now()->subDays(7))
                ->orderByDesc('created_at')
                ->limit(5)
                ->get();

            if ($events->count() > 0) {
                $this->info('Recent Security Events (last 7 days)');
                $this->line(str_repeat('-', 20));
                foreach ($events as $event) {
                    $date = $event->created_at->format('Y-m-d');
                    $this->line(" * {$date}: {$event->description}");
                }
                $this->newLine();
            }
        }
    }

    /**
     * Display summary table.
     *
     * @param  array<string, mixed>  $stats
     */
    protected function displaySummaryTable(array $stats): void
    {
        $this->info('User Security Summary');
        $this->line(str_repeat('=', 30));
        $this->newLine();

        $this->line("<fg=white;options=bold>Total Users:</> {$stats['total_users']}");
        $this->newLine();

        $this->info('Security Overview');
        $this->line(str_repeat('-', 20));

        $rows = [
            ['Users without 2FA', $stats['without_2fa']],
            ['Locked accounts', $stats['locked_accounts']],
            ['Users with suspicious activity', $stats['suspicious_activity']],
            ['Old passwords (>90 days)', $stats['old_passwords']],
        ];

        $this->table(['Metric', 'Count'], $rows);

        $this->newLine();
        $this->info('API Tokens');
        $this->line(str_repeat('-', 20));

        $tokenRows = [
            ['Expiring soon (7 days)', $stats['expiring_tokens_7d']],
            ['Never-expiring tokens', $stats['never_expiring_tokens']],
        ];

        $this->table(['Metric', 'Count'], $tokenRows);

        $this->newLine();
        $this->info('Sessions & Events');
        $this->line(str_repeat('-', 20));

        $sessionRows = [
            ['Active sessions', $stats['active_sessions']],
            ['Users with >3 sessions', $stats['users_multiple_sessions']],
            ['Security events (24h)', $stats['security_events_24h']],
            ['Failed logins (24h)', $stats['failed_logins_24h']],
        ];

        $this->table(['Metric', 'Count'], $sessionRows);

        $this->newLine();
        $this->line("Run '<fg=cyan>security:user-security --all --issues-only</>' for detailed analysis");
    }

    /**
     * Display all users report.
     *
     * @param  array<int, array<string, mixed>>  $results
     * @param  Collection<int, array<string, mixed>>  $allIssues
     */
    protected function displayAllUsersReport(array $results, int $usersWithIssues, Collection $allIssues): void
    {
        $this->info('User Security Scan Results');
        $this->line(str_repeat('=', 30));
        $this->newLine();

        $this->line('<fg=white;options=bold>Summary:</>');
        $this->line(" Users scanned: ".count($results));
        $this->line(" Users with issues: {$usersWithIssues}");
        $this->line(' Total issues found: '.$allIssues->count());
        $this->newLine();

        // Issue breakdown
        $bySeverity = $allIssues->groupBy('severity');
        $this->info('Issues by Severity');
        $this->table(
            ['Severity', 'Count'],
            [
                ['<fg=red>High</>', $bySeverity->get('high', collect())->count()],
                ['<fg=yellow>Medium</>', $bySeverity->get('medium', collect())->count()],
                ['<fg=cyan>Low</>', $bySeverity->get('low', collect())->count()],
            ]
        );

        // Issue breakdown by type
        $byType = $allIssues->groupBy('type');
        $this->newLine();
        $this->info('Issues by Type');
        $typeRows = [];
        foreach ($byType as $type => $issues) {
            $typeRows[] = [ucfirst($type), $issues->count()];
        }
        $this->table(['Type', 'Count'], $typeRows);

        // High-risk users
        $highRiskUsers = collect($results)->filter(function ($data) {
            return $data['issues']->where('severity', 'high')->count() > 0;
        })->take(10);

        if ($highRiskUsers->count() > 0) {
            $this->newLine();
            $this->warn('High-Risk Users');
            $this->line(str_repeat('-', 20));

            foreach ($highRiskUsers as $data) {
                $user = $data['user'];
                $issues = $data['issues']->where('severity', 'high');
                $issueList = $issues->pluck('title')->implode(', ');
                $this->line(" - {$user->email}: {$issueList}");
            }
        }
    }

    /**
     * Output user data as JSON.
     *
     * @param  Collection<int, array<string, mixed>>  $issues
     */
    protected function outputUserJson(Model $user, Collection $issues): void
    {
        $data = [
            'user_id' => $user->getKey(),
            'email' => $user->email ?? null,
            'security_score' => $this->calculateSecurityScore($issues),
            'issues_count' => $issues->count(),
            'issues' => $issues->toArray(),
        ];

        $this->line(json_encode($data, JSON_PRETTY_PRINT));
    }

    /**
     * Output all users data as JSON.
     *
     * @param  array<int, array<string, mixed>>  $results
     */
    protected function outputAllUsersJson(array $results): void
    {
        $data = [
            'scan_date' => now()->toIso8601String(),
            'users_scanned' => count($results),
            'users' => [],
        ];

        foreach ($results as $userId => $result) {
            $data['users'][] = [
                'user_id' => $userId,
                'email' => $result['user']->email ?? null,
                'security_score' => $this->calculateSecurityScore($result['issues']),
                'issues_count' => $result['issues']->count(),
                'issues' => $result['issues']->toArray(),
            ];
        }

        $this->line(json_encode($data, JSON_PRETTY_PRINT));
    }

    /**
     * Export results to file.
     *
     * @param  array<int, Collection<int, array<string, mixed>>>  $results
     */
    protected function exportResults(array $results, string $path): void
    {
        $data = [];

        foreach ($results as $userId => $issues) {
            $data[] = [
                'user_id' => $userId,
                'issues' => $issues instanceof Collection ? $issues->toArray() : $issues,
            ];
        }

        $json = json_encode([
            'export_date' => now()->toIso8601String(),
            'results' => $data,
        ], JSON_PRETTY_PRINT);

        File::put($path, $json);
        $this->info("Results exported to: {$path}");
    }
}
