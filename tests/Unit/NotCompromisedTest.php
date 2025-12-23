<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use ArtisanPackUI\Security\Rules\NotCompromised;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use Tests\Concerns\ValidatesInput;
use Tests\TestCase;

class NotCompromisedTest extends TestCase
{
    use ValidatesInput;

    protected function setUp(): void
    {
        parent::setUp();

        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', true);
    }

    #[Test]
    public function it_passes_when_password_not_compromised()
    {
        $this->mockBreachChecker(0);

        $rule = new NotCompromised();

        $this->assertValidates($rule, 'NotCompromisedPassword123!');
    }

    #[Test]
    public function it_fails_when_password_is_compromised()
    {
        $this->mockBreachChecker(1000);

        $rule = new NotCompromised();

        $this->assertFailsValidation($rule, 'password123');
    }

    #[Test]
    public function it_respects_threshold()
    {
        // Password appears 5 times in breaches
        $this->mockBreachChecker(5);

        // Threshold of 10, should pass
        $ruleWithHighThreshold = new NotCompromised(10);
        $this->assertValidates($ruleWithHighThreshold, 'Password123!');

        // Re-mock for next test
        $this->mockBreachChecker(5);

        // Threshold of 0 (default), should fail
        $ruleWithNoThreshold = new NotCompromised(0);
        $this->assertFailsValidation($ruleWithNoThreshold, 'Password123!');
    }

    #[Test]
    public function it_passes_when_breach_checking_disabled()
    {
        Config::set('artisanpack.security.passwordSecurity.breachChecking.enabled', false);

        // Even with a compromised password, should pass when disabled
        $this->mockBreachChecker(10000);

        $rule = new NotCompromised();

        $this->assertValidates($rule, 'password');
    }

    #[Test]
    public function it_returns_detailed_message_with_count()
    {
        $this->mockBreachChecker(12345);

        $rule = new NotCompromised();
        $rule->passes('password', 'compromised');

        $message = $rule->message();

        $this->assertStringContainsString('12,345', $message);
        $this->assertStringContainsString('data breach', $message);
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
