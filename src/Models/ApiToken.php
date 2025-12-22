<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Builder;
use Laravel\Sanctum\PersonalAccessToken;

class ApiToken extends PersonalAccessToken
{
    /**
     * The table associated with the model.
     * We use Sanctum's personal_access_tokens table with our additional columns.
     *
     * @var string
     */
    protected $table = 'personal_access_tokens';

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'abilities' => 'array',
        'metadata' => 'array',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
        'is_revoked' => 'boolean',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'name',
        'token',
        'abilities',
        'expires_at',
        'ip_address',
        'user_agent',
        'metadata',
        'is_revoked',
        'revoked_at',
    ];

    /**
     * Scope a query to only include active tokens.
     * Active tokens are not revoked and not expired.
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query
            ->where('is_revoked', false)
            ->where(function (Builder $q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    /**
     * Scope a query to only include expired tokens.
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now());
    }

    /**
     * Scope a query to only include revoked tokens.
     */
    public function scopeRevoked(Builder $query): Builder
    {
        return $query->where('is_revoked', true);
    }

    /**
     * Scope a query to only include tokens that haven't been used in a given number of days.
     */
    public function scopeUnusedFor(Builder $query, int $days): Builder
    {
        return $query->where(function (Builder $q) use ($days) {
            $q->whereNull('last_used_at')
                ->orWhere('last_used_at', '<', now()->subDays($days));
        });
    }

    /**
     * Check if the token is expired.
     */
    public function isExpired(): bool
    {
        if ($this->expires_at === null) {
            return false;
        }

        return $this->expires_at->isPast();
    }

    /**
     * Check if the token is valid (not expired and not revoked).
     */
    public function isValid(): bool
    {
        return ! $this->is_revoked && ! $this->isExpired();
    }

    /**
     * Revoke this token.
     */
    public function revoke(): bool
    {
        return $this->update([
            'is_revoked' => true,
            'revoked_at' => now(),
        ]);
    }

    /**
     * Check if the token has a specific ability.
     */
    public function hasAbility(string $ability): bool
    {
        return in_array('*', $this->abilities ?? [], true)
            || in_array($ability, $this->abilities ?? [], true);
    }

    /**
     * Check if the token has all of the given abilities.
     */
    public function hasAllAbilities(array $abilities): bool
    {
        if (in_array('*', $this->abilities ?? [], true)) {
            return true;
        }

        foreach ($abilities as $ability) {
            if (! $this->hasAbility($ability)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the token has any of the given abilities.
     */
    public function hasAnyAbility(array $abilities): bool
    {
        if (in_array('*', $this->abilities ?? [], true)) {
            return true;
        }

        foreach ($abilities as $ability) {
            if ($this->hasAbility($ability)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the human-readable expiration status.
     */
    public function getExpirationStatusAttribute(): string
    {
        if ($this->is_revoked) {
            return 'Revoked';
        }

        if ($this->expires_at === null) {
            return 'Never expires';
        }

        if ($this->isExpired()) {
            return 'Expired ' . $this->expires_at->diffForHumans();
        }

        return 'Expires ' . $this->expires_at->diffForHumans();
    }

    /**
     * Get metadata value by key.
     */
    public function getMetadata(string $key, mixed $default = null): mixed
    {
        return data_get($this->metadata, $key, $default);
    }

    /**
     * Set metadata value by key.
     */
    public function setMetadata(string $key, mixed $value): bool
    {
        $metadata = $this->metadata ?? [];
        data_set($metadata, $key, $value);

        return $this->update(['metadata' => $metadata]);
    }

    /**
     * Record token usage information.
     */
    public function recordUsage(?string $ipAddress = null, ?string $userAgent = null): bool
    {
        $data = ['last_used_at' => now()];

        if ($ipAddress !== null) {
            $data['ip_address'] = $ipAddress;
        }

        if ($userAgent !== null) {
            $data['user_agent'] = $userAgent;
        }

        return $this->update($data);
    }
}
