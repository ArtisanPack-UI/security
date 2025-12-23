<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use ArtisanPackUI\Security\Contracts\PasswordSecurityServiceInterface;
use ArtisanPackUI\Security\Models\PasswordHistory;
use ArtisanPackUI\Security\Rules\PasswordComplexity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Hash;

class PasswordSecurityService implements PasswordSecurityServiceInterface
{
    /**
     * The breach checker instance.
     */
    protected BreachCheckerInterface $breachChecker;

    /**
     * Create a new service instance.
     */
    public function __construct(BreachCheckerInterface $breachChecker)
    {
        $this->breachChecker = $breachChecker;
    }

    /**
     * Validate a password against all configured policies.
     */
    public function validatePassword(string $password, ?Authenticatable $user = null): array
    {
        $errors = [];

        // Check complexity
        $complexityErrors = $this->checkComplexity($password, $user);
        $errors = array_merge($errors, $complexityErrors);

        // Check history if user provided
        if ($user !== null && $this->isInHistory($password, $user)) {
            $count = config('artisanpack.security.passwordSecurity.history.count', 5);
            $errors[] = "You cannot reuse any of your last {$count} passwords.";
        }

        // Check if password change is allowed (minimum days between changes)
        if ($user !== null && method_exists($user, 'canChangePassword') && ! $user->canChangePassword()) {
            $days = method_exists($user, 'daysUntilCanChangePassword')
                ? $user->daysUntilCanChangePassword()
                : config('artisanpack.security.passwordSecurity.history.minDaysBetweenChanges', 1);
            $errors[] = "You must wait {$days} more day(s) before changing your password again.";
        }

        // Check breach status
        if (config('artisanpack.security.passwordSecurity.breachChecking.enabled', true)) {
            if (config('artisanpack.security.passwordSecurity.breachChecking.blockCompromised', true)) {
                $occurrences = $this->breachChecker->check($password);
                if ($occurrences > 0) {
                    $errors[] = sprintf(
                        'This password has appeared in %s data breach(es) and should not be used.',
                        number_format($occurrences)
                    );
                }
            }
        }

        return $errors;
    }

    /**
     * Check if a password meets complexity requirements.
     */
    public function checkComplexity(string $password, ?Authenticatable $user = null): array
    {
        $rule = new PasswordComplexity($user);

        if (! $rule->passes('password', $password)) {
            $message = $rule->message();

            return is_array($message) ? $message : [$message];
        }

        return [];
    }

    /**
     * Check if password exists in user's history.
     */
    public function isInHistory(string $password, Authenticatable $user): bool
    {
        if (! config('artisanpack.security.passwordSecurity.history.enabled', false)) {
            return false;
        }

        if (method_exists($user, 'passwordExistsInHistory')) {
            return $user->passwordExistsInHistory($password);
        }

        // Fallback: query directly
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);

        $recentPasswords = PasswordHistory::forUser($user->getAuthIdentifier(), $count)
            ->pluck('password_hash');

        foreach ($recentPasswords as $hashedPassword) {
            if (Hash::check($password, $hashedPassword)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Record a password in user's history.
     */
    public function recordPassword(string $hashedPassword, Authenticatable $user): void
    {
        if (! config('artisanpack.security.passwordSecurity.history.enabled', false)) {
            return;
        }

        if (method_exists($user, 'recordPasswordInHistory')) {
            $user->recordPasswordInHistory($hashedPassword);

            return;
        }

        // Fallback: insert directly
        PasswordHistory::create([
            'user_id' => $user->getAuthIdentifier(),
            'password_hash' => $hashedPassword,
            'created_at' => now(),
        ]);

        $this->pruneHistory($user);
    }

    /**
     * Check if user's password has expired.
     */
    public function isExpired(Authenticatable $user): bool
    {
        if (! config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
            return false;
        }

        if (method_exists($user, 'passwordHasExpired')) {
            return $user->passwordHasExpired();
        }

        // Fallback: check directly if user has the column
        if (isset($user->password_expires_at) && $user->password_expires_at !== null) {
            return $user->password_expires_at->isPast();
        }

        return false;
    }

    /**
     * Get days until password expires.
     */
    public function daysUntilExpiration(Authenticatable $user): ?int
    {
        if (method_exists($user, 'daysUntilPasswordExpires')) {
            return $user->daysUntilPasswordExpires();
        }

        if (isset($user->password_expires_at) && $user->password_expires_at !== null) {
            $days = (int) now()->diffInDays($user->password_expires_at, false);

            return max(0, $days);
        }

        return null;
    }

    /**
     * Check if password has been compromised in known breaches.
     */
    public function isCompromised(string $password): bool
    {
        return $this->breachChecker->isCompromised($password);
    }

    /**
     * Calculate password strength score (0-4).
     */
    public function calculateStrength(string $password, array $userInputs = []): array
    {
        // Check if zxcvbn-php is available
        if (class_exists(\ZxcvbnPhp\Zxcvbn::class)) {
            return $this->calculateStrengthWithZxcvbn($password, $userInputs);
        }

        // Fallback to simple strength calculation
        return $this->calculateStrengthSimple($password);
    }

    /**
     * Calculate strength using zxcvbn-php library.
     */
    protected function calculateStrengthWithZxcvbn(string $password, array $userInputs): array
    {
        $zxcvbn = new \ZxcvbnPhp\Zxcvbn();
        $result = $zxcvbn->passwordStrength($password, $userInputs);

        $labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

        return [
            'score' => $result['score'],
            'label' => $labels[$result['score']] ?? 'Unknown',
            'crackTime' => $result['crack_times_display']['offline_slow_hashing_1e4_per_second'] ?? '',
            'feedback' => array_merge(
                $result['feedback']['warning'] ? [$result['feedback']['warning']] : [],
                $result['feedback']['suggestions'] ?? []
            ),
        ];
    }

    /**
     * Calculate strength using simple algorithm (fallback).
     */
    protected function calculateStrengthSimple(string $password): array
    {
        $score = 0;
        $feedback = [];
        $length = strlen($password);

        // Length scoring
        if ($length >= 8) {
            $score++;
        } else {
            $feedback[] = 'Add more characters to strengthen your password.';
        }

        if ($length >= 12) {
            $score++;
        }

        // Character variety
        $hasLower = preg_match('/[a-z]/', $password);
        $hasUpper = preg_match('/[A-Z]/', $password);
        $hasNumber = preg_match('/[0-9]/', $password);
        $hasSymbol = preg_match('/[^A-Za-z0-9]/', $password);

        $variety = $hasLower + $hasUpper + $hasNumber + $hasSymbol;

        if ($variety >= 3) {
            $score++;
        } elseif ($variety < 2) {
            $feedback[] = 'Use a mix of uppercase, lowercase, numbers, and symbols.';
        }

        if ($variety === 4 && $length >= 12) {
            $score++;
        }

        // Unique characters
        $uniqueChars = count(array_unique(str_split($password)));
        if ($uniqueChars < 5) {
            $feedback[] = 'Avoid repeating characters.';
        }

        // Cap at 4
        $score = min(4, $score);

        $labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

        // Estimate crack time based on score
        $crackTimes = [
            'instantly',
            'minutes',
            'hours',
            'days',
            'centuries',
        ];

        return [
            'score' => $score,
            'label' => $labels[$score],
            'crackTime' => $crackTimes[$score],
            'feedback' => $feedback,
        ];
    }

    /**
     * Prune old password history records.
     */
    public function pruneHistory(Authenticatable $user): int
    {
        if (method_exists($user, 'prunePasswordHistory')) {
            return $user->prunePasswordHistory();
        }

        // Fallback: prune directly
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);
        $userId = $user->getAuthIdentifier();

        $idsToKeep = PasswordHistory::forUser($userId, $count)->pluck('id');

        return PasswordHistory::where('user_id', $userId)
            ->whereNotIn('id', $idsToKeep)
            ->delete();
    }
}
