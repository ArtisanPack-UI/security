<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use ArtisanPackUI\Security\Services\PasswordSecurityService;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class PasswordSecurityServiceTest extends TestCase
{
    protected PasswordSecurityService $service;

    protected function setUp(): void
    {
        parent::setUp();

        Config::set('artisanpack.security.passwordSecurity.enabled', true);
        Config::set('artisanpack.security.passwordSecurity.complexity', [
            'minLength' => 8,
            'maxLength' => 128,
            'requireUppercase' => true,
            'requireLowercase' => true,
            'requireNumbers' => true,
            'requireSymbols' => true,
            'minUniqueCharacters' => 4,
            'disallowRepeatingCharacters' => 3,
            'disallowSequentialCharacters' => 3,
            'disallowUserAttributes' => true,
        ]);
        Config::set('artisanpack.security.passwordSecurity.history.enabled', false);
        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', true);
        Config::set('artisanpack.security.passwordSecurity.breachChecking.blockCompromised', true);

        $this->mockBreachChecker(0);
        $this->service = $this->app->make(PasswordSecurityService::class);
    }

    #[Test]
    public function it_validates_password_successfully()
    {
        $errors = $this->service->validatePassword('MyStr0ng!Pass');

        $this->assertEmpty($errors);
    }

    #[Test]
    public function it_returns_errors_for_invalid_password()
    {
        $errors = $this->service->validatePassword('weak');

        $this->assertNotEmpty($errors);
    }

    #[Test]
    public function it_checks_complexity()
    {
        $errors = $this->service->checkComplexity('MyStr0ng!Pass');
        $this->assertEmpty($errors);

        $errors = $this->service->checkComplexity('weak');
        $this->assertNotEmpty($errors);
    }

    #[Test]
    public function it_checks_breach_status()
    {
        $this->mockBreachChecker(0);
        $service = $this->app->make(PasswordSecurityService::class);

        $this->assertFalse($service->isCompromised('safe_password'));

        $this->mockBreachChecker(1000);
        $service = $this->app->make(PasswordSecurityService::class);

        $this->assertTrue($service->isCompromised('compromised_password'));
    }

    #[Test]
    public function it_includes_breach_errors_in_validation()
    {
        $this->mockBreachChecker(500);
        $service = $this->app->make(PasswordSecurityService::class);

        $errors = $service->validatePassword('MyStr0ng!Pass');

        $this->assertNotEmpty($errors);
        $this->assertTrue(
            collect($errors)->contains(fn ($error) => str_contains($error, 'breach'))
        );
    }

    #[Test]
    public function it_skips_breach_check_when_disabled()
    {
        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', false);

        $this->mockBreachChecker(1000000);
        $service = $this->app->make(PasswordSecurityService::class);

        $errors = $service->validatePassword('MyStr0ng!Pass');

        $this->assertEmpty($errors);
    }

    #[Test]
    public function it_calculates_strength_score()
    {
        $result = $this->service->calculateStrength('MyStr0ng!P@ssword123');

        $this->assertArrayHasKey('score', $result);
        $this->assertArrayHasKey('label', $result);
        $this->assertArrayHasKey('crackTime', $result);
        $this->assertArrayHasKey('feedback', $result);

        $this->assertGreaterThanOrEqual(0, $result['score']);
        $this->assertLessThanOrEqual(4, $result['score']);
    }

    #[Test]
    public function it_returns_low_score_for_weak_password()
    {
        $result = $this->service->calculateStrength('abc');

        $this->assertLessThanOrEqual(1, $result['score']);
        $this->assertNotEmpty($result['feedback']);
    }

    #[Test]
    public function it_returns_high_score_for_strong_password()
    {
        $result = $this->service->calculateStrength('MyV3ry$tr0ng&C0mpl3xP@ssw0rd!');

        $this->assertGreaterThanOrEqual(3, $result['score']);
    }

    #[Test]
    public function it_includes_user_inputs_in_strength_calculation()
    {
        // Password containing user's name should be penalized
        $resultWithInputs = $this->service->calculateStrength('JohnSmith123!', ['john', 'smith']);
        $resultWithoutInputs = $this->service->calculateStrength('JohnSmith123!', []);

        // When user inputs are provided, strength should be lower or equal
        $this->assertLessThanOrEqual($resultWithoutInputs['score'], $resultWithInputs['score']);
    }

    #[Test]
    public function strength_labels_are_correct()
    {
        $weakResult = $this->service->calculateStrength('a');
        $strongResult = $this->service->calculateStrength('MyV3ry$tr0ng&C0mpl3xP@ss!');

        $validLabels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

        $this->assertContains($weakResult['label'], $validLabels);
        $this->assertContains($strongResult['label'], $validLabels);
    }

    /**
     * Mock the breach checker service.
     */
    protected function mockBreachChecker(int $occurrences): void
    {
        $mock = $this->createMock(BreachCheckerInterface::class);
        $mock->method('check')->willReturn($occurrences);
        $mock->method('isCompromised')->willReturn($occurrences > 0);

        $this->app->instance(BreachCheckerInterface::class, $mock);
    }
}
