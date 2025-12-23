<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Rules\PasswordComplexity;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use Tests\Concerns\ValidatesInput;
use Tests\TestCase;

class PasswordComplexityTest extends TestCase
{
    use ValidatesInput;

    protected function setUp(): void
    {
        parent::setUp();

        // Set default configuration
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
    }

    #[Test]
    public function it_validates_minimum_length()
    {
        $rule = new PasswordComplexity();

        // Too short
        $this->assertFailsValidation($rule, 'Aa1!');

        // Exactly minimum length - need to avoid sequences
        $this->assertValidates($rule, 'Xpwd12!@');
    }

    #[Test]
    public function it_validates_maximum_length()
    {
        Config::set('artisanpack.security.passwordSecurity.complexity.maxLength', 20);

        $rule = new PasswordComplexity();

        // Too long (21 chars)
        $this->assertFailsValidation($rule, 'Xpwdxpwdxpwdxpwd12!@#');

        // Within limit - avoid sequences
        $this->assertValidates($rule, 'Xpwdxpwdxp12!@');
    }

    #[Test]
    public function it_requires_uppercase_letter()
    {
        $rule = new PasswordComplexity();

        // No uppercase
        $this->assertFailsValidation($rule, 'xpwdxpwd12!@');

        // Has uppercase - avoid sequences
        $this->assertValidates($rule, 'Xpwdxpwd12!@');
    }

    #[Test]
    public function it_requires_lowercase_letter()
    {
        $rule = new PasswordComplexity();

        // No lowercase
        $this->assertFailsValidation($rule, 'XPWDXPWD12!@');

        // Has lowercase - avoid sequences
        $this->assertValidates($rule, 'XPWDxpwd12!@');
    }

    #[Test]
    public function it_requires_numbers()
    {
        $rule = new PasswordComplexity();

        // No numbers
        $this->assertFailsValidation($rule, 'Xpwdxpwd!@#$');

        // Has numbers - avoid sequences
        $this->assertValidates($rule, 'Xpwdxpwd12!@');
    }

    #[Test]
    public function it_requires_symbols()
    {
        $rule = new PasswordComplexity();

        // No symbols
        $this->assertFailsValidation($rule, 'Xpwdxpwd1279');

        // Has symbols - avoid sequences
        $this->assertValidates($rule, 'Xpwdxpwd12!@');
    }

    #[Test]
    public function it_requires_minimum_unique_characters()
    {
        Config::set('artisanpack.security.passwordSecurity.complexity.minUniqueCharacters', 6);

        $rule = new PasswordComplexity();

        // Not enough unique characters (only 4: X, a, 1, !)
        $this->assertFailsValidation($rule, 'Xaaa1111!!!!');

        // Enough unique characters (X, p, w, d, 1, 2, !, @)
        $this->assertValidates($rule, 'Xpwdxp12!@');
    }

    #[Test]
    public function it_disallows_repeating_characters()
    {
        $rule = new PasswordComplexity();

        // Has 4+ repeating characters (xxxx)
        $this->assertFailsValidation($rule, 'Pxxxxwd12!@');

        // Only 3 repeating characters (allowed)
        $this->assertValidates($rule, 'Pxxxwd12!@');
    }

    #[Test]
    public function it_disallows_sequential_characters()
    {
        $rule = new PasswordComplexity();

        // Has sequential characters (abcd = 4 sequential)
        $this->assertFailsValidation($rule, 'Xyzabcd12!@');

        // Has reverse sequential characters (dcba = 4 sequential)
        $this->assertFailsValidation($rule, 'Xyzdcba12!@');

        // Has numeric sequence (12345 = 5 sequential)
        $this->assertFailsValidation($rule, 'Xyz12345!@#');

        // No sequential characters (wvut is not sequential - 4 chars but non-consecutive)
        $this->assertValidates($rule, 'Xyzwpt12!@');
    }

    #[Test]
    public function it_disallows_keyboard_sequences()
    {
        $rule = new PasswordComplexity();

        // Has keyboard sequence (qwert = 5 sequential on keyboard)
        $this->assertFailsValidation($rule, 'Xyzqwert12!@');

        // No keyboard sequence
        $this->assertValidates($rule, 'Xyzpmk12!@');
    }

    #[Test]
    public function it_disallows_user_attributes_in_password()
    {
        // Create a mock user that implements Authenticatable
        $user = new class extends User {
            protected $guarded = [];

            public function __construct()
            {
                parent::__construct([
                    'email' => 'johndoe@example.com',
                    'name' => 'JohnSmith',
                    'username' => 'jsmith',
                ]);
            }
        };

        $rule = new PasswordComplexity($user);

        // Contains email local part (johndoe)
        $this->assertFailsValidation($rule, 'johndoe12!@XY');

        // Contains name (case-insensitive)
        $this->assertFailsValidation($rule, 'Johnsmith12!@XY');

        // Contains username
        $this->assertFailsValidation($rule, 'Jsmith12!@XYZ');

        // Doesn't contain user attributes
        $this->assertValidates($rule, 'Pmkqrt12!@');
    }

    #[Test]
    public function it_respects_disabled_requirements()
    {
        Config::set('artisanpack.security.passwordSecurity.complexity.requireUppercase', false);
        Config::set('artisanpack.security.passwordSecurity.complexity.requireSymbols', false);
        Config::set('artisanpack.security.passwordSecurity.complexity.disallowSequentialCharacters', 0);

        $rule = new PasswordComplexity();

        // No uppercase or symbols, but should pass
        $this->assertValidates($rule, 'abcdefgh1234');
    }

    #[Test]
    public function it_returns_multiple_errors()
    {
        $rule = new PasswordComplexity();

        // Multiple issues: too short, no uppercase, no number, no symbol
        $result = $rule->passes('password', 'abc');
        $errors = $rule->message();

        $this->assertFalse($result);
        $this->assertIsArray($errors);
        $this->assertGreaterThan(1, count($errors));
    }

    #[Test]
    public function it_validates_strong_password()
    {
        $rule = new PasswordComplexity();

        $this->assertValidates($rule, 'MyStr0ng!P@ssword');
        $this->assertValidates($rule, 'C0mplex#Pass917');
        $this->assertValidates($rule, 'Secur3&Unique99');
    }
}
