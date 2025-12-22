<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing;

use ArtisanPackUI\Security\Models\ApiToken;
use Illuminate\Testing\TestResponse;

trait ApiSecurityAssertions
{
    /**
     * Create an API token for testing.
     *
     * @param  mixed  $user  The user model instance
     * @param  array  $abilities  Token abilities
     * @param  int|null  $expiresInMinutes  Token expiration
     * @return string The plain text token
     */
    protected function createTestApiToken(
        $user,
        array $abilities = ['*'],
        ?int $expiresInMinutes = null
    ): string {
        if (method_exists($user, 'createApiToken')) {
            return $user->createApiToken('test-token', $abilities, $expiresInMinutes)->plainTextToken;
        }

        return $user->createToken('test-token', $abilities)->plainTextToken;
    }

    /**
     * Create an expired token for testing.
     *
     * @param  mixed  $user  The user model instance
     * @param  array  $abilities  Token abilities
     * @return string The plain text token
     */
    protected function createExpiredTestApiToken($user, array $abilities = ['*']): string
    {
        $token = $user->createToken('expired-test-token', $abilities);

        // Set expiration to the past
        $token->accessToken->update([
            'expires_at' => now()->subHour(),
        ]);

        return $token->plainTextToken;
    }

    /**
     * Create a revoked token for testing.
     *
     * @param  mixed  $user  The user model instance
     * @param  array  $abilities  Token abilities
     * @return string The plain text token
     */
    protected function createRevokedTestApiToken($user, array $abilities = ['*']): string
    {
        $token = $user->createToken('revoked-test-token', $abilities);

        $token->accessToken->update([
            'is_revoked' => true,
            'revoked_at' => now(),
        ]);

        return $token->plainTextToken;
    }

    /**
     * Assert the response indicates authentication is required.
     */
    protected function assertRequiresAuthentication(TestResponse $response): void
    {
        $response->assertStatus(401);
    }

    /**
     * Assert the response indicates insufficient permissions.
     */
    protected function assertRequiresAbility(TestResponse $response, ?string $ability = null): void
    {
        $response->assertStatus(403);

        if ($ability !== null) {
            $response->assertJson([
                'error' => 'insufficient_ability',
            ]);
        }
    }

    /**
     * Assert the request was rate limited.
     */
    protected function assertRateLimited(TestResponse $response): void
    {
        $response->assertStatus(429);
        $response->assertHeader('Retry-After');
    }

    /**
     * Assert the token is valid and not expired.
     */
    protected function assertTokenValid(string $plainTextToken): void
    {
        [$id, $token] = explode('|', $plainTextToken, 2);

        $accessToken = ApiToken::find($id);

        $this->assertNotNull($accessToken, 'Token not found in database');
        $this->assertFalse($accessToken->is_revoked, 'Token is revoked');
        $this->assertFalse($accessToken->isExpired(), 'Token is expired');
    }

    /**
     * Assert the token has specific abilities.
     */
    protected function assertTokenHasAbilities(string $plainTextToken, array $abilities): void
    {
        [$id, $token] = explode('|', $plainTextToken, 2);

        $accessToken = ApiToken::find($id);

        $this->assertNotNull($accessToken, 'Token not found in database');

        foreach ($abilities as $ability) {
            $this->assertTrue(
                $accessToken->hasAbility($ability),
                "Token does not have ability: {$ability}"
            );
        }
    }

    /**
     * Assert the token is revoked.
     */
    protected function assertTokenRevoked(string $plainTextToken): void
    {
        [$id, $token] = explode('|', $plainTextToken, 2);

        $accessToken = ApiToken::find($id);

        $this->assertNotNull($accessToken, 'Token not found in database');
        $this->assertTrue($accessToken->is_revoked, 'Token is not revoked');
    }

    /**
     * Assert the token is expired.
     */
    protected function assertTokenExpired(string $plainTextToken): void
    {
        [$id, $token] = explode('|', $plainTextToken, 2);

        $accessToken = ApiToken::find($id);

        $this->assertNotNull($accessToken, 'Token not found in database');
        $this->assertTrue($accessToken->isExpired(), 'Token is not expired');
    }

    /**
     * Act as a user with a specific API token.
     *
     * @param  mixed  $user  The user model instance
     * @param  array  $abilities  Token abilities
     * @return $this
     */
    protected function actingAsApiUser($user, array $abilities = ['*']): self
    {
        $token = $this->createTestApiToken($user, $abilities);

        return $this->withHeader('Authorization', 'Bearer ' . $token);
    }

    /**
     * Make an authenticated API request.
     *
     * @param  mixed  $user  The user model instance
     * @param  string  $method  HTTP method
     * @param  string  $uri  Request URI
     * @param  array  $data  Request data
     * @param  array  $abilities  Token abilities
     * @return TestResponse
     */
    protected function apiAs($user, string $method, string $uri, array $data = [], array $abilities = ['*']): TestResponse
    {
        $token = $this->createTestApiToken($user, $abilities);

        return $this->withHeader('Authorization', 'Bearer ' . $token)
            ->json($method, $uri, $data);
    }

    /**
     * Make an API request with a specific token.
     *
     * @param  string  $token  The plain text token
     * @param  string  $method  HTTP method
     * @param  string  $uri  Request URI
     * @param  array  $data  Request data
     * @return TestResponse
     */
    protected function apiWithToken(string $token, string $method, string $uri, array $data = []): TestResponse
    {
        return $this->withHeader('Authorization', 'Bearer ' . $token)
            ->json($method, $uri, $data);
    }
}
