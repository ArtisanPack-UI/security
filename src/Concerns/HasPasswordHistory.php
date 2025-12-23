<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\PasswordHistory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Hash;

/**
 * Trait HasPasswordHistory
 *
 * Add this trait to your User model to enable password history tracking,
 * expiration checking, and related functionality.
 *
 * Required columns on users table (added by migration):
 * - password_changed_at (timestamp, nullable)
 * - password_expires_at (timestamp, nullable)
 * - force_password_change (boolean, default false)
 * - grace_logins_remaining (tinyint unsigned, nullable)
 */
trait HasPasswordHistory
{
    /**
     * Boot the trait.
     */
    public static function bootHasPasswordHistory(): void
    {
        // When password is updated, record in history
        static::updating(function ($user) {
            if ($user->isDirty('password') && config('artisanpack.security.passwordSecurity.history.enabled', false)) {
                $originalPassword = $user->getOriginal('password');
                if ($originalPassword) {
                    $user->recordPasswordInHistory($originalPassword);
                }

                // Update password_changed_at timestamp
                $user->password_changed_at = now();

                // Calculate new expiration if enabled
                if (config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
                    $days = config('artisanpack.security.passwordSecurity.expiration.days', 90);
                    $user->password_expires_at = now()->addDays($days);
                }

                // Reset force change flag
                $user->force_password_change = false;
                $user->grace_logins_remaining = null;
            }
        });
    }

    /**
     * Get the user's password history.
     */
    public function passwordHistory(): HasMany
    {
        return $this->hasMany(PasswordHistory::class, 'user_id');
    }

    /**
     * Record a password hash in history.
     */
    public function recordPasswordInHistory(string $hashedPassword): void
    {
        $this->passwordHistory()->create([
            'password_hash' => $hashedPassword,
            'created_at' => now(),
        ]);

        // Prune old history entries
        $this->prunePasswordHistory();
    }

    /**
     * Check if a plain-text password matches any in history.
     */
    public function passwordExistsInHistory(string $password): bool
    {
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);

        $recentPasswords = $this->passwordHistory()
            ->orderByDesc('created_at')
            ->limit($count)
            ->pluck('password_hash');

        foreach ($recentPasswords as $hashedPassword) {
            if (Hash::check($password, $hashedPassword)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Prune old password history entries beyond the configured count.
     */
    public function prunePasswordHistory(): int
    {
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);

        $idsToKeep = $this->passwordHistory()
            ->orderByDesc('created_at')
            ->limit($count)
            ->pluck('id');

        return $this->passwordHistory()
            ->whereNotIn('id', $idsToKeep)
            ->delete();
    }

    /**
     * Check if password has expired.
     */
    public function passwordHasExpired(): bool
    {
        if (! config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
            return false;
        }

        // Check exempt roles
        $exemptRoles = config('artisanpack.security.passwordSecurity.expiration.exemptRoles', []);
        if (method_exists($this, 'hasRole')) {
            foreach ($exemptRoles as $role) {
                if ($this->hasRole($role)) {
                    return false;
                }
            }
        }

        if ($this->password_expires_at === null) {
            return false;
        }

        return $this->password_expires_at->isPast();
    }

    /**
     * Check if password is expiring soon.
     */
    public function passwordExpiringSoon(): bool
    {
        if (! config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
            return false;
        }

        if ($this->password_expires_at === null) {
            return false;
        }

        $warningDays = config('artisanpack.security.passwordSecurity.expiration.warningDays', 14);

        return $this->password_expires_at->isBetween(now(), now()->addDays($warningDays));
    }

    /**
     * Get days until password expires.
     */
    public function daysUntilPasswordExpires(): ?int
    {
        if ($this->password_expires_at === null) {
            return null;
        }

        $days = (int) now()->diffInDays($this->password_expires_at, false);

        return max(0, $days);
    }

    /**
     * Check if user can still login with grace period.
     */
    public function hasGraceLoginsRemaining(): bool
    {
        return $this->grace_logins_remaining !== null && $this->grace_logins_remaining > 0;
    }

    /**
     * Decrement grace logins.
     */
    public function decrementGraceLogins(): void
    {
        if ($this->grace_logins_remaining !== null && $this->grace_logins_remaining > 0) {
            $this->decrement('grace_logins_remaining');
        }
    }

    /**
     * Initialize grace logins for a user whose password has expired.
     */
    public function initializeGraceLogins(): void
    {
        $graceLogins = config('artisanpack.security.passwordSecurity.expiration.graceLogins', 3);
        $this->update(['grace_logins_remaining' => $graceLogins]);
    }

    /**
     * Check if the minimum days between password changes has passed.
     */
    public function canChangePassword(): bool
    {
        $minDays = config('artisanpack.security.passwordSecurity.history.minDaysBetweenChanges', 1);

        if ($minDays <= 0 || $this->password_changed_at === null) {
            return true;
        }

        return $this->password_changed_at->addDays($minDays)->isPast();
    }

    /**
     * Get the number of days until the user can change their password.
     */
    public function daysUntilCanChangePassword(): ?int
    {
        $minDays = config('artisanpack.security.passwordSecurity.history.minDaysBetweenChanges', 1);

        if ($minDays <= 0 || $this->password_changed_at === null) {
            return 0;
        }

        $canChangeAt = $this->password_changed_at->addDays($minDays);

        if ($canChangeAt->isPast()) {
            return 0;
        }

        return (int) now()->diffInDays($canChangeAt, false);
    }
}
