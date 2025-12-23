<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface PasswordSecurityServiceInterface
{
    /**
     * Validate a password against all configured policies.
     *
     * @param  string  $password  The plain-text password to validate
     * @param  Authenticatable|null  $user  Optional user for context-aware validation
     * @return array Array of error messages (empty if valid)
     */
    public function validatePassword(string $password, ?Authenticatable $user = null): array;

    /**
     * Check if a password meets complexity requirements.
     *
     * @param  string  $password  The plain-text password to check
     * @param  Authenticatable|null  $user  Optional user for context-aware validation
     * @return array Array of error messages (empty if valid)
     */
    public function checkComplexity(string $password, ?Authenticatable $user = null): array;

    /**
     * Check if password exists in user's history.
     *
     * @param  string  $password  The plain-text password to check
     * @param  Authenticatable  $user  The user whose history to check
     * @return bool True if password exists in history
     */
    public function isInHistory(string $password, Authenticatable $user): bool;

    /**
     * Record a password in user's history.
     *
     * @param  string  $hashedPassword  The hashed password to record
     * @param  Authenticatable  $user  The user to record for
     */
    public function recordPassword(string $hashedPassword, Authenticatable $user): void;

    /**
     * Check if user's password has expired.
     *
     * @param  Authenticatable  $user  The user to check
     * @return bool True if password has expired
     */
    public function isExpired(Authenticatable $user): bool;

    /**
     * Get days until password expires.
     *
     * @param  Authenticatable  $user  The user to check
     * @return int|null Days until expiration, null if no expiration
     */
    public function daysUntilExpiration(Authenticatable $user): ?int;

    /**
     * Check if password has been compromised in known breaches.
     *
     * @param  string  $password  The plain-text password to check
     * @return bool True if password has been compromised
     */
    public function isCompromised(string $password): bool;

    /**
     * Calculate password strength score (0-4).
     *
     * @param  string  $password  The password to evaluate
     * @param  array  $userInputs  Additional inputs to penalize (e.g., username, email)
     * @return array Contains 'score', 'label', 'crackTime', and 'feedback'
     */
    public function calculateStrength(string $password, array $userInputs = []): array;

    /**
     * Prune old password history records.
     *
     * @param  Authenticatable  $user  The user whose history to prune
     * @return int Number of records deleted
     */
    public function pruneHistory(Authenticatable $user): int;
}
