<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\ApiToken;
use Illuminate\Support\Collection;
use Laravel\Sanctum\HasApiTokens as SanctumHasApiTokens;
use Laravel\Sanctum\NewAccessToken;

trait HasApiTokens
{
    use SanctumHasApiTokens;

    /**
     * Create a new API token with expiration and metadata.
     */
    public function createApiToken(
        string $name,
        array $abilities = ['*'],
        ?int $expiresInMinutes = null,
        array $metadata = []
    ): NewAccessToken {
        // Use configured expiration if not specified
        if ($expiresInMinutes === null) {
            $expiresInMinutes = config('artisanpack.security.api.tokens.expiration');
        }

        // Add configured prefix to token name
        $prefix = config('artisanpack.security.api.tokens.prefix');
        if ($prefix && ! str_starts_with($name, $prefix)) {
            $name = $prefix . '_' . $name;
        }

        // Create the token using Sanctum's method
        $token = $this->createToken($name, $abilities);

        // Add our extensions
        $token->accessToken->update([
            'expires_at' => $expiresInMinutes ? now()->addMinutes($expiresInMinutes) : null,
            'ip_address' => request()?->ip(),
            'user_agent' => request()?->userAgent(),
            'metadata' => $metadata ?: null,
        ]);

        return $token;
    }

    /**
     * Create a token using an ability group name.
     */
    public function createApiTokenWithGroup(
        string $name,
        string $group,
        ?int $expiresInMinutes = null,
        array $metadata = []
    ): NewAccessToken {
        $groups = config('artisanpack.security.api.ability_groups', []);

        if (! isset($groups[$group])) {
            throw new \InvalidArgumentException("Unknown ability group: {$group}");
        }

        return $this->createApiToken($name, $groups[$group], $expiresInMinutes, $metadata);
    }

    /**
     * Get all active (non-expired, non-revoked) tokens.
     */
    public function activeApiTokens(): Collection
    {
        return $this->tokens()
            ->where('is_revoked', false)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->get();
    }

    /**
     * Get all tokens including expired and revoked.
     */
    public function allApiTokens(): Collection
    {
        return $this->tokens()->get();
    }

    /**
     * Revoke a specific token by ID.
     */
    public function revokeApiToken(int $tokenId): bool
    {
        $token = $this->tokens()->find($tokenId);

        if (! $token) {
            return false;
        }

        return $token->update([
            'is_revoked' => true,
            'revoked_at' => now(),
        ]);
    }

    /**
     * Revoke all tokens for this user.
     */
    public function revokeAllApiTokens(): int
    {
        return $this->tokens()
            ->where('is_revoked', false)
            ->update([
                'is_revoked' => true,
                'revoked_at' => now(),
            ]);
    }

    /**
     * Revoke all tokens except the current one.
     */
    public function revokeOtherApiTokens(): int
    {
        $currentToken = $this->currentAccessToken();

        $query = $this->tokens()->where('is_revoked', false);

        if ($currentToken) {
            $query->where('id', '!=', $currentToken->id);
        }

        return $query->update([
            'is_revoked' => true,
            'revoked_at' => now(),
        ]);
    }

    /**
     * Check if user has any active tokens.
     */
    public function hasActiveApiTokens(): bool
    {
        return $this->activeApiTokens()->isNotEmpty();
    }

    /**
     * Prune expired tokens for this user.
     */
    public function pruneExpiredApiTokens(): int
    {
        return $this->tokens()
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now())
            ->delete();
    }

    /**
     * Prune revoked tokens for this user.
     */
    public function pruneRevokedApiTokens(): int
    {
        return $this->tokens()
            ->where('is_revoked', true)
            ->delete();
    }

    /**
     * Get token usage statistics.
     */
    public function apiTokenStats(): array
    {
        $tokens = $this->tokens()->get();

        $active = $tokens->filter(fn ($t) => ! $t->is_revoked && ($t->expires_at === null || $t->expires_at->isFuture()));
        $expired = $tokens->filter(fn ($t) => $t->expires_at !== null && $t->expires_at->isPast());
        $revoked = $tokens->filter(fn ($t) => $t->is_revoked);

        return [
            'total' => $tokens->count(),
            'active' => $active->count(),
            'expired' => $expired->count(),
            'revoked' => $revoked->count(),
            'last_used' => $tokens->max('last_used_at'),
            'last_created' => $tokens->max('created_at'),
        ];
    }

    /**
     * Find a token by its ID.
     */
    public function findApiToken(int $tokenId): ?ApiToken
    {
        return $this->tokens()->find($tokenId);
    }

    /**
     * Check if the user has a token with the given ability.
     */
    public function hasApiTokenWithAbility(string $ability): bool
    {
        return $this->activeApiTokens()
            ->filter(function ($token) use ($ability) {
                return in_array('*', $token->abilities ?? [], true)
                    || in_array($ability, $token->abilities ?? [], true);
            })
            ->isNotEmpty();
    }
}
