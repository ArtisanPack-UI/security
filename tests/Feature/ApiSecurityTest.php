<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Models\ApiToken;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Tests\Models\ApiTestUser;

class ApiSecurityTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \Laravel\Sanctum\SanctumServiceProvider::class,
            \ArtisanPackUI\Security\SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        Config::set('artisanpack.security.api.enabled', true);
        Config::set('artisanpack.security.api.tokens.expiration', 60 * 24 * 7);
        Config::set('artisanpack.security.api.tokens.prefix', 'test');
        // Disable Sanctum's built-in expiration so our middleware handles it
        Config::set('sanctum.expiration', null);
        Config::set('artisanpack.security.api.ability_groups', [
            'readonly' => ['read'],
            'standard' => ['read', 'write'],
            'admin' => ['read', 'write', 'delete', 'admin'],
        ]);

        Config::set('database.default', 'testbench');
        Config::set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        Config::set('auth.providers.users.model', ApiTestUser::class);

        // Create users table
        $app['db']->connection()->getSchemaBuilder()->create('users', function ($table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email');
            $table->timestamps();
        });

        // Create personal_access_tokens table (Sanctum's table with our extensions)
        $app['db']->connection()->getSchemaBuilder()->create('personal_access_tokens', function ($table) {
            $table->id();
            $table->morphs('tokenable');
            $table->string('name');
            $table->string('token', 64)->unique();
            $table->text('abilities')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
            // Our extended columns
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->json('metadata')->nullable();
            $table->boolean('is_revoked')->default(false);
            $table->timestamp('revoked_at')->nullable();
        });
    }

    public function setUp(): void
    {
        parent::setUp();
    }

    // ==================== Token Creation Tests ====================

    #[Test]
    public function it_can_create_an_api_token()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $token = $user->createApiToken('test-token');

        $this->assertNotNull($token->plainTextToken);
        $this->assertDatabaseHas('personal_access_tokens', [
            'tokenable_id' => $user->id,
        ]);
    }

    #[Test]
    public function it_creates_token_with_abilities()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $token = $user->createApiToken('test-token', ['read', 'write']);

        $this->assertEquals(['read', 'write'], $token->accessToken->abilities);
    }

    #[Test]
    public function it_creates_token_with_expiration()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $token = $user->createApiToken('test-token', ['*'], 60);

        $this->assertNotNull($token->accessToken->expires_at);
        $this->assertTrue($token->accessToken->expires_at->isFuture());
    }

    #[Test]
    public function it_creates_token_with_ability_group()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $token = $user->createApiTokenWithGroup('admin-token', 'admin');

        $this->assertEquals(['read', 'write', 'delete', 'admin'], $token->accessToken->abilities);
    }

    #[Test]
    public function it_throws_exception_for_invalid_ability_group()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $this->expectException(\InvalidArgumentException::class);

        $user->createApiTokenWithGroup('token', 'invalid-group');
    }

    // ==================== Token Model Tests ====================

    #[Test]
    public function token_is_valid_when_not_expired_and_not_revoked()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token');

        $this->assertTrue($token->accessToken->isValid());
    }

    #[Test]
    public function token_is_expired_when_past_expiration()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['*'], 60);

        // Manually set expiration to the past
        $token->accessToken->update(['expires_at' => now()->subHour()]);

        $this->assertTrue($token->accessToken->isExpired());
        $this->assertFalse($token->accessToken->isValid());
    }

    #[Test]
    public function token_can_be_revoked()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token');

        $token->accessToken->revoke();

        $this->assertTrue($token->accessToken->is_revoked);
        $this->assertNotNull($token->accessToken->revoked_at);
        $this->assertFalse($token->accessToken->isValid());
    }

    #[Test]
    public function token_has_ability_check_works()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['read', 'write']);

        $this->assertTrue($token->accessToken->hasAbility('read'));
        $this->assertTrue($token->accessToken->hasAbility('write'));
        $this->assertFalse($token->accessToken->hasAbility('delete'));
    }

    #[Test]
    public function token_with_wildcard_has_all_abilities()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['*']);

        $this->assertTrue($token->accessToken->hasAbility('read'));
        $this->assertTrue($token->accessToken->hasAbility('anything'));
    }

    #[Test]
    public function token_has_all_abilities_check_works()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['read', 'write']);

        $this->assertTrue($token->accessToken->hasAllAbilities(['read', 'write']));
        $this->assertFalse($token->accessToken->hasAllAbilities(['read', 'delete']));
    }

    #[Test]
    public function token_has_any_ability_check_works()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['read']);

        $this->assertTrue($token->accessToken->hasAnyAbility(['read', 'write']));
        $this->assertFalse($token->accessToken->hasAnyAbility(['write', 'delete']));
    }

    // ==================== Token Management Tests ====================

    #[Test]
    public function it_can_get_active_tokens()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $user->createApiToken('active-token');
        $expiredToken = $user->createApiToken('expired-token');
        $expiredToken->accessToken->update(['expires_at' => now()->subHour()]);
        $revokedToken = $user->createApiToken('revoked-token');
        $revokedToken->accessToken->revoke();

        $activeTokens = $user->activeApiTokens();

        $this->assertCount(1, $activeTokens);
    }

    #[Test]
    public function it_can_revoke_specific_token()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token');

        $result = $user->revokeApiToken($token->accessToken->id);

        $this->assertTrue($result);
        $token->accessToken->refresh();
        $this->assertTrue($token->accessToken->is_revoked);
    }

    #[Test]
    public function it_can_revoke_all_tokens()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('token-1');
        $user->createApiToken('token-2');
        $user->createApiToken('token-3');

        $count = $user->revokeAllApiTokens();

        $this->assertEquals(3, $count);
        $this->assertCount(0, $user->activeApiTokens());
    }

    #[Test]
    public function it_can_prune_expired_tokens()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('active-token');
        $expiredToken = $user->createApiToken('expired-token');
        $expiredToken->accessToken->update(['expires_at' => now()->subHour()]);

        $count = $user->pruneExpiredApiTokens();

        $this->assertEquals(1, $count);
        $this->assertCount(1, $user->allApiTokens());
    }

    #[Test]
    public function it_can_get_token_stats()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('active-token');
        $expiredToken = $user->createApiToken('expired-token');
        $expiredToken->accessToken->update(['expires_at' => now()->subHour()]);
        $revokedToken = $user->createApiToken('revoked-token');
        $revokedToken->accessToken->revoke();

        $stats = $user->apiTokenStats();

        $this->assertEquals(3, $stats['total']);
        $this->assertEquals(1, $stats['active']);
        $this->assertEquals(1, $stats['expired']);
        $this->assertEquals(1, $stats['revoked']);
    }

    // ==================== Model Scope Tests ====================

    #[Test]
    public function active_scope_filters_correctly()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('active-token');
        $expiredToken = $user->createApiToken('expired-token');
        $expiredToken->accessToken->update(['expires_at' => now()->subHour()]);
        $revokedToken = $user->createApiToken('revoked-token');
        $revokedToken->accessToken->revoke();

        $activeTokens = ApiToken::active()->get();

        $this->assertCount(1, $activeTokens);
    }

    #[Test]
    public function expired_scope_filters_correctly()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('active-token');
        $expiredToken = $user->createApiToken('expired-token');
        $expiredToken->accessToken->update(['expires_at' => now()->subHour()]);

        $expiredTokens = ApiToken::expired()->get();

        $this->assertCount(1, $expiredTokens);
    }

    #[Test]
    public function revoked_scope_filters_correctly()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('active-token');
        $revokedToken = $user->createApiToken('revoked-token');
        $revokedToken->accessToken->revoke();

        $revokedTokens = ApiToken::revoked()->get();

        $this->assertCount(1, $revokedTokens);
    }

    // ==================== Middleware Tests ====================

    #[Test]
    public function api_security_middleware_rejects_revoked_token()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token');
        $token->accessToken->revoke();

        Route::middleware(['auth:sanctum', 'api.security'])->get('/api-test', function () {
            return response()->json(['success' => true]);
        });

        $response = $this->withHeader('Authorization', 'Bearer ' . $token->plainTextToken)
            ->getJson('/api-test');

        $response->assertStatus(401);
        $response->assertJson(['error' => 'token_revoked']);
    }

    #[Test]
    public function api_security_middleware_rejects_expired_token()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['*'], 60);
        $token->accessToken->update(['expires_at' => now()->subHour()]);

        Route::middleware(['auth:sanctum', 'api.security'])->get('/api-test', function () {
            return response()->json(['success' => true]);
        });

        $response = $this->withHeader('Authorization', 'Bearer ' . $token->plainTextToken)
            ->getJson('/api-test');

        // Sanctum handles expiration at the auth layer via the expires_at column,
        // returning a generic 401 before our middleware runs
        $response->assertStatus(401);
    }

    #[Test]
    public function api_security_middleware_allows_valid_token()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token');

        Route::middleware(['auth:sanctum', 'api.security'])->get('/api-test', function () {
            return response()->json(['success' => true]);
        });

        $response = $this->withHeader('Authorization', 'Bearer ' . $token->plainTextToken)
            ->getJson('/api-test');

        $response->assertStatus(200);
    }

    #[Test]
    public function token_ability_middleware_rejects_missing_ability()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['read']);

        Route::middleware(['auth:sanctum', 'token.ability:write'])->get('/api-test', function () {
            return response()->json(['success' => true]);
        });

        $response = $this->withHeader('Authorization', 'Bearer ' . $token->plainTextToken)
            ->getJson('/api-test');

        $response->assertStatus(403);
        $response->assertJson(['error' => 'insufficient_ability']);
    }

    #[Test]
    public function token_ability_middleware_allows_matching_ability()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['read', 'write']);

        Route::middleware(['auth:sanctum', 'token.ability:write'])->get('/api-test', function () {
            return response()->json(['success' => true]);
        });

        $response = $this->withHeader('Authorization', 'Bearer ' . $token->plainTextToken)
            ->getJson('/api-test');

        $response->assertStatus(200);
    }

    #[Test]
    public function token_ability_any_middleware_allows_any_matching_ability()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['read']);

        Route::middleware(['auth:sanctum', 'token.ability.any:write,read'])->get('/api-test', function () {
            return response()->json(['success' => true]);
        });

        $response = $this->withHeader('Authorization', 'Bearer ' . $token->plainTextToken)
            ->getJson('/api-test');

        $response->assertStatus(200);
    }

    #[Test]
    public function token_ability_any_middleware_rejects_no_matching_ability()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token', ['read']);

        Route::middleware(['auth:sanctum', 'token.ability.any:write,delete'])->get('/api-test', function () {
            return response()->json(['success' => true]);
        });

        $response = $this->withHeader('Authorization', 'Bearer ' . $token->plainTextToken)
            ->getJson('/api-test');

        $response->assertStatus(403);
    }

    // ==================== Artisan Command Tests ====================

    #[Test]
    public function it_can_create_token_via_command()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $this->artisan('api:token:create', [
            'user' => $user->id,
            '--name' => 'CLI Token',
        ])->assertSuccessful();

        $this->assertDatabaseHas('personal_access_tokens', [
            'tokenable_id' => $user->id,
        ]);
    }

    #[Test]
    public function it_can_create_token_with_abilities_via_command()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $this->artisan('api:token:create', [
            'user' => $user->id,
            '--name' => 'CLI Token',
            '--abilities' => ['read', 'write'],
        ])->assertSuccessful();

        $token = ApiToken::where('tokenable_id', $user->id)->first();
        $this->assertEquals(['read', 'write'], $token->abilities);
    }

    #[Test]
    public function it_can_create_token_with_group_via_command()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);

        $this->artisan('api:token:create', [
            'user' => $user->id,
            '--name' => 'Admin Token',
            '--group' => 'admin',
        ])->assertSuccessful();

        $token = ApiToken::where('tokenable_id', $user->id)->first();
        $this->assertEquals(['read', 'write', 'delete', 'admin'], $token->abilities);
    }

    #[Test]
    public function it_can_list_tokens_via_command()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('token-1');
        $user->createApiToken('token-2');

        $this->artisan('api:token:list')
            ->assertSuccessful()
            ->expectsOutputToContain('Total: 2 token(s)');
    }

    #[Test]
    public function it_can_revoke_token_via_command()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $token = $user->createApiToken('test-token');

        $this->artisan('api:token:revoke', [
            'token' => $token->accessToken->id,
        ])->assertSuccessful();

        $token->accessToken->refresh();
        $this->assertTrue($token->accessToken->is_revoked);
    }

    #[Test]
    public function it_can_prune_expired_tokens_via_command()
    {
        $user = ApiTestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $user->createApiToken('active-token');
        $expiredToken = $user->createApiToken('expired-token');
        $expiredToken->accessToken->update(['expires_at' => now()->subHour()]);

        $this->artisan('api:token:prune', [
            '--expired' => true,
            '--force' => true,
        ])->assertSuccessful();

        $this->assertCount(1, ApiToken::all());
    }

    #[Test]
    public function api_security_check_command_runs()
    {
        $this->artisan('api:security:check')
            ->assertSuccessful();
    }
}
