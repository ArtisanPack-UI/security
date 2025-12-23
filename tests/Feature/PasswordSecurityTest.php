<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use ArtisanPackUI\Security\Models\PasswordHistory;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Tests\Models\TestUserWithPasswordHistory;

class PasswordSecurityTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \ArtisanPackUI\Security\SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        Config::set('artisanpack.security.passwordSecurity.enabled', true);
        Config::set('artisanpack.security.passwordSecurity.history.enabled', true);
        Config::set('artisanpack.security.passwordSecurity.history.count', 3);
        Config::set('artisanpack.security.passwordSecurity.expiration.enabled', false);
        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', false);

        Config::set('database.default', 'testbench');
        Config::set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        Config::set('auth.providers.users.model', TestUserWithPasswordHistory::class);

        // Create users table with password security columns
        $app['db']->connection()->getSchemaBuilder()->create('users', function ($table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email');
            $table->string('password');
            $table->timestamp('password_changed_at')->nullable();
            $table->timestamp('password_expires_at')->nullable();
            $table->boolean('force_password_change')->default(false);
            $table->unsignedTinyInteger('grace_logins_remaining')->nullable();
            $table->timestamps();
        });
    }

    public function setUp(): void
    {
        parent::setUp();

        $this->artisan('migrate', ['--database' => 'testbench'])->run();

        // Mock breach checker to always return safe
        $mock = $this->createMock(BreachCheckerInterface::class);
        $mock->method('check')->willReturn(0);
        $mock->method('isCompromised')->willReturn(false);
        $this->app->instance(BreachCheckerInterface::class, $mock);
    }

    #[Test]
    public function it_records_password_in_history_when_changed()
    {
        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('OldPassword123!'),
        ]);

        $originalPasswordHash = $user->password;

        // Change the password
        $user->password = Hash::make('NewPassword123!');
        $user->save();

        // Check that the old password was recorded in history
        $this->assertDatabaseHas('password_history', [
            'user_id' => $user->id,
        ]);

        $historyEntry = PasswordHistory::where('user_id', $user->id)->first();
        $this->assertEquals($originalPasswordHash, $historyEntry->password_hash);
    }

    #[Test]
    public function it_detects_password_in_history()
    {
        $password = 'TestPassword123!';
        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make($password),
        ]);

        // Record password in history manually
        PasswordHistory::create([
            'user_id' => $user->id,
            'password_hash' => Hash::make($password),
            'created_at' => now(),
        ]);

        // Check if password exists in history
        $this->assertTrue($user->passwordExistsInHistory($password));
        $this->assertFalse($user->passwordExistsInHistory('DifferentPassword123!'));
    }

    #[Test]
    public function it_prunes_old_password_history()
    {
        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password1!'),
        ]);

        // Add 5 passwords to history (more than the configured 3)
        for ($i = 1; $i <= 5; $i++) {
            PasswordHistory::create([
                'user_id' => $user->id,
                'password_hash' => Hash::make("Password{$i}!"),
                'created_at' => now()->subDays(5 - $i),
            ]);
        }

        $this->assertEquals(5, PasswordHistory::where('user_id', $user->id)->count());

        // Prune history
        $deleted = $user->prunePasswordHistory();

        $this->assertEquals(2, $deleted);
        $this->assertEquals(3, PasswordHistory::where('user_id', $user->id)->count());
    }

    #[Test]
    public function it_updates_password_changed_at_timestamp()
    {
        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('OldPassword123!'),
            'password_changed_at' => null,
        ]);

        $this->assertNull($user->password_changed_at);

        // Change password
        $user->password = Hash::make('NewPassword123!');
        $user->save();

        $user->refresh();
        $this->assertNotNull($user->password_changed_at);
    }

    #[Test]
    public function it_checks_password_expiration()
    {
        Config::set('artisanpack.security.passwordSecurity.expiration.enabled', true);

        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'password_expires_at' => now()->subDay(),
        ]);

        $this->assertTrue($user->passwordHasExpired());

        $user->password_expires_at = now()->addDays(30);
        $user->save();

        $this->assertFalse($user->passwordHasExpired());
    }

    #[Test]
    public function it_checks_password_expiring_soon()
    {
        Config::set('artisanpack.security.passwordSecurity.expiration.enabled', true);
        Config::set('artisanpack.security.passwordSecurity.expiration.warningDays', 14);

        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'password_expires_at' => now()->addDays(7), // Expires in 7 days
        ]);

        $this->assertTrue($user->passwordExpiringSoon());

        $user->password_expires_at = now()->addDays(30); // Expires in 30 days
        $user->save();

        $this->assertFalse($user->passwordExpiringSoon());
    }

    #[Test]
    public function it_calculates_days_until_expiration()
    {
        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'password_expires_at' => now()->addDays(10),
        ]);

        $days = $user->daysUntilPasswordExpires();

        // Allow for slight time differences during test execution
        $this->assertGreaterThanOrEqual(9, $days);
        $this->assertLessThanOrEqual(10, $days);
    }

    #[Test]
    public function it_handles_grace_logins()
    {
        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'grace_logins_remaining' => 3,
        ]);

        $this->assertTrue($user->hasGraceLoginsRemaining());

        $user->decrementGraceLogins();
        $user->refresh();

        $this->assertEquals(2, $user->grace_logins_remaining);
        $this->assertTrue($user->hasGraceLoginsRemaining());

        // Decrement to zero
        $user->update(['grace_logins_remaining' => 1]);
        $user->decrementGraceLogins();
        $user->refresh();

        $this->assertEquals(0, $user->grace_logins_remaining);
        $this->assertFalse($user->hasGraceLoginsRemaining());
    }

    #[Test]
    public function it_checks_minimum_days_between_changes()
    {
        Config::set('artisanpack.security.passwordSecurity.history.minDaysBetweenChanges', 1);

        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'password_changed_at' => now(),
        ]);

        // Just changed, should not be able to change again
        $this->assertFalse($user->canChangePassword());

        // Changed yesterday, should be able to change
        $user->password_changed_at = now()->subDays(2);
        $user->save();

        $this->assertTrue($user->canChangePassword());
    }

    #[Test]
    public function enforce_password_policy_middleware_rejects_weak_password()
    {
        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', false);

        Route::post('/test-password', function () {
            return response()->json(['success' => true]);
        })->middleware('password.policy');

        $response = $this->postJson('/test-password', [
            'password' => 'weak',
        ]);

        $response->assertStatus(422);
        $response->assertJsonStructure(['message', 'errors' => ['password']]);
    }

    #[Test]
    public function enforce_password_policy_middleware_accepts_strong_password()
    {
        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', false);

        Route::post('/test-password', function () {
            return response()->json(['success' => true]);
        })->middleware('password.policy');

        $response = $this->postJson('/test-password', [
            'password' => 'MyStr0ng!P@ssword',
        ]);

        $response->assertStatus(200);
    }

    #[Test]
    public function require_password_change_middleware_redirects_when_expired()
    {
        Config::set('artisanpack.security.passwordSecurity.expiration.enabled', true);

        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'password_expires_at' => now()->subDay(),
            'grace_logins_remaining' => 0,
        ]);

        Route::get('/password/change', function () {
            return 'Change Password Page';
        })->name('password.change');

        Route::get('/protected', function () {
            return 'Protected Content';
        })->middleware(['auth', 'password.change']);

        $this->actingAs($user);

        $response = $this->get('/protected');

        $response->assertRedirect(route('password.change'));
    }

    #[Test]
    public function require_password_change_middleware_allows_when_not_expired()
    {
        Config::set('artisanpack.security.passwordSecurity.expiration.enabled', true);

        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'password_expires_at' => now()->addDays(30),
        ]);

        Route::get('/protected', function () {
            return 'Protected Content';
        })->middleware(['auth', 'password.change']);

        $this->actingAs($user);

        $response = $this->get('/protected');

        $response->assertStatus(200);
        $response->assertSee('Protected Content');
    }

    #[Test]
    public function require_password_change_middleware_handles_force_change_flag()
    {
        Config::set('artisanpack.security.passwordSecurity.expiration.enabled', true);

        $user = TestUserWithPasswordHistory::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('Password123!'),
            'force_password_change' => true,
        ]);

        Route::get('/password/change', function () {
            return 'Change Password Page';
        })->name('password.change');

        Route::get('/protected', function () {
            return 'Protected Content';
        })->middleware(['auth', 'password.change']);

        $this->actingAs($user);

        $response = $this->get('/protected');

        $response->assertRedirect(route('password.change'));
    }

    #[Test]
    public function password_security_is_disabled_when_config_disabled()
    {
        Config::set('artisanpack.security.passwordSecurity.enabled', false);

        Route::post('/test-password', function () {
            return response()->json(['success' => true]);
        })->middleware('password.policy');

        $response = $this->postJson('/test-password', [
            'password' => 'weak', // Would normally fail
        ]);

        $response->assertStatus(200);
    }
}
