<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Analytics\Listeners;

use ArtisanPackUI\Security\Analytics\MetricsCollector;
use ArtisanPackUI\Security\Events\AccountLocked;
use ArtisanPackUI\Security\Events\AccountUnlocked;
use ArtisanPackUI\Security\Events\PasswordChanged;
use ArtisanPackUI\Security\Events\SuspiciousActivityDetected;
use ArtisanPackUI\Security\Events\TwoFactorAuthenticationDisabled;
use ArtisanPackUI\Security\Events\TwoFactorAuthenticationEnabled;
use ArtisanPackUI\Security\Events\TwoFactorVerified;
use ArtisanPackUI\Security\Models\SecurityMetric;

class SecurityEventMetricsListener
{
    public function __construct(
        protected MetricsCollector $collector
    ) {}

    /**
     * Handle account locked event.
     */
    public function handleAccountLocked(AccountLocked $event): void
    {
        $this->collector->recordThreatEvent('account_locked', 'high', [
            'identifier' => $event->identifier,
            'reason' => $event->reason,
            'duration_minutes' => $event->durationMinutes,
        ]);

        $this->collector->increment(
            'security.account_locks',
            1,
            SecurityMetric::CATEGORY_THREAT
        );
    }

    /**
     * Handle account unlocked event.
     */
    public function handleAccountUnlocked(AccountUnlocked $event): void
    {
        $this->collector->recordAuthEvent('account_unlocked', true, [
            'identifier' => $event->identifier,
        ]);
    }

    /**
     * Handle password changed event.
     */
    public function handlePasswordChanged(PasswordChanged $event): void
    {
        $this->collector->recordAuthEvent('password_changed', true, [
            'user_id' => $event->user->getAuthIdentifier(),
        ]);
    }

    /**
     * Handle suspicious activity detected event.
     */
    public function handleSuspiciousActivity(SuspiciousActivityDetected $event): void
    {
        $this->collector->recordThreatEvent(
            'suspicious_activity',
            $event->severity,
            [
                'type' => $event->type,
                'user_id' => $event->userId,
                'ip' => $event->ipAddress,
            ]
        );

        $this->collector->increment(
            "security.suspicious.{$event->type}",
            1,
            SecurityMetric::CATEGORY_THREAT,
            ['severity' => $event->severity]
        );
    }

    /**
     * Handle 2FA enabled event.
     */
    public function handleTwoFactorEnabled(TwoFactorAuthenticationEnabled $event): void
    {
        $this->collector->recordAuthEvent('2fa_enabled', true, [
            'user_id' => $event->user->getAuthIdentifier(),
        ]);

        $this->collector->increment(
            'security.2fa_enabled',
            1,
            SecurityMetric::CATEGORY_COMPLIANCE
        );
    }

    /**
     * Handle 2FA disabled event.
     */
    public function handleTwoFactorDisabled(TwoFactorAuthenticationDisabled $event): void
    {
        $this->collector->recordAuthEvent('2fa_disabled', true, [
            'user_id' => $event->user->getAuthIdentifier(),
        ]);

        // Track as a potential security concern
        $this->collector->recordThreatEvent('2fa_disabled', 'low', [
            'user_id' => $event->user->getAuthIdentifier(),
        ]);
    }

    /**
     * Handle 2FA verified event.
     */
    public function handleTwoFactorVerified(TwoFactorVerified $event): void
    {
        $this->collector->recordAuthEvent('2fa_verified', true, [
            'user_id' => $event->user->getAuthIdentifier(),
        ]);
    }

    /**
     * Subscribe to security events.
     *
     * @param  \Illuminate\Events\Dispatcher  $events
     */
    public function subscribe($events): void
    {
        $events->listen(AccountLocked::class, [self::class, 'handleAccountLocked']);
        $events->listen(AccountUnlocked::class, [self::class, 'handleAccountUnlocked']);
        $events->listen(PasswordChanged::class, [self::class, 'handlePasswordChanged']);
        $events->listen(SuspiciousActivityDetected::class, [self::class, 'handleSuspiciousActivity']);
        $events->listen(TwoFactorAuthenticationEnabled::class, [self::class, 'handleTwoFactorEnabled']);
        $events->listen(TwoFactorAuthenticationDisabled::class, [self::class, 'handleTwoFactorDisabled']);
        $events->listen(TwoFactorVerified::class, [self::class, 'handleTwoFactorVerified']);
    }
}
