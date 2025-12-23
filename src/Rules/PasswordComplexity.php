<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\Rule;

class PasswordComplexity implements Rule
{
    /**
     * The validation errors.
     *
     * @var array<int, string>
     */
    protected array $errors = [];

    /**
     * The user for context-aware validation.
     */
    protected ?Authenticatable $user;

    /**
     * Create a new rule instance.
     */
    public function __construct(?Authenticatable $user = null)
    {
        $this->user = $user;
    }

    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     */
    public function passes($attribute, $value): bool
    {
        $this->errors = [];
        $config = config('artisanpack.security.passwordSecurity.complexity', []);

        // Length checks
        $minLength = $config['minLength'] ?? 8;
        $maxLength = $config['maxLength'] ?? 128;

        if (strlen($value) < $minLength) {
            $this->errors[] = "Password must be at least {$minLength} characters.";
        }

        if (strlen($value) > $maxLength) {
            $this->errors[] = "Password must not exceed {$maxLength} characters.";
        }

        // Character type requirements
        if (($config['requireUppercase'] ?? true) && ! preg_match('/[A-Z]/', $value)) {
            $this->errors[] = 'Password must contain at least one uppercase letter.';
        }

        if (($config['requireLowercase'] ?? true) && ! preg_match('/[a-z]/', $value)) {
            $this->errors[] = 'Password must contain at least one lowercase letter.';
        }

        if (($config['requireNumbers'] ?? true) && ! preg_match('/[0-9]/', $value)) {
            $this->errors[] = 'Password must contain at least one number.';
        }

        if (($config['requireSymbols'] ?? true) && ! preg_match('/[^A-Za-z0-9]/', $value)) {
            $this->errors[] = 'Password must contain at least one special character.';
        }

        // Unique characters
        $minUnique = $config['minUniqueCharacters'] ?? 4;
        if (count(array_unique(str_split($value))) < $minUnique) {
            $this->errors[] = "Password must contain at least {$minUnique} unique characters.";
        }

        // Repeating characters
        $maxRepeat = $config['disallowRepeatingCharacters'] ?? 3;
        if ($maxRepeat > 0 && preg_match('/(.)\1{' . $maxRepeat . ',}/', $value)) {
            $this->errors[] = "Password must not contain more than {$maxRepeat} consecutive repeating characters.";
        }

        // Sequential characters
        $maxSequential = $config['disallowSequentialCharacters'] ?? 3;
        if ($maxSequential > 0 && $this->hasSequentialCharacters($value, $maxSequential)) {
            $this->errors[] = "Password must not contain more than {$maxSequential} sequential characters.";
        }

        // User attributes check
        if (($config['disallowUserAttributes'] ?? true) && $this->user) {
            $this->checkUserAttributes($value);
        }

        return empty($this->errors);
    }

    /**
     * Get the validation error message.
     *
     * @return array<int, string>|string
     */
    public function message(): array|string
    {
        return $this->errors;
    }

    /**
     * Check if password contains sequential characters.
     */
    protected function hasSequentialCharacters(string $value, int $maxSequential): bool
    {
        $sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '0123456789',
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
        ];

        $lowerValue = strtolower($value);

        foreach ($sequences as $sequence) {
            $sequence = strtolower($sequence);
            $chunkSize = $maxSequential + 1;
            for ($i = 0; $i <= strlen($sequence) - $chunkSize; $i++) {
                $chunk = substr($sequence, $i, $chunkSize);
                if (str_contains($lowerValue, $chunk)) {
                    return true;
                }
                // Check reverse
                if (str_contains($lowerValue, strrev($chunk))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if password contains user attributes.
     */
    protected function checkUserAttributes(string $value): void
    {
        $lowerValue = strtolower($value);
        $attributes = ['email', 'name', 'username', 'first_name', 'last_name'];

        foreach ($attributes as $attr) {
            if (isset($this->user->{$attr})) {
                $attrValue = strtolower((string) $this->user->{$attr});
                // Check if attribute value (or parts of it) are in password
                if (strlen($attrValue) >= 3) {
                    // Check email local part
                    if ($attr === 'email') {
                        $localPart = explode('@', $attrValue)[0];
                        if (strlen($localPart) >= 3 && str_contains($lowerValue, $localPart)) {
                            $this->errors[] = 'Password must not contain parts of your email address.';

                            continue;
                        }
                    }

                    if (str_contains($lowerValue, $attrValue)) {
                        $this->errors[] = "Password must not contain your {$attr}.";
                    }
                }
            }
        }
    }
}
