<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Rules;

use ArtisanPackUI\Security\Contracts\BreachCheckerInterface;
use Illuminate\Contracts\Validation\Rule;

class NotCompromised implements Rule
{
    /**
     * The threshold for the number of times a password can appear in breaches.
     */
    protected int $threshold;

    /**
     * The number of times the password was found in breaches.
     */
    protected int $occurrences = 0;

    /**
     * Create a new rule instance.
     *
     * @param  int  $threshold  Allow passwords that appear this many times or less in breaches
     */
    public function __construct(int $threshold = 0)
    {
        $this->threshold = $threshold;
    }

    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     */
    public function passes($attribute, $value): bool
    {
        if (! config('artisanpack.security.passwordSecurity.breachChecking.enabled', true)) {
            return true;
        }

        $checker = app(BreachCheckerInterface::class);
        $this->occurrences = $checker->check($value);

        return $this->occurrences <= $this->threshold;
    }

    /**
     * Get the validation error message.
     */
    public function message(): string
    {
        if ($this->occurrences > 0) {
            return sprintf(
                'This password has appeared in %s data breach(es) and should not be used. Please choose a different password.',
                number_format($this->occurrences)
            );
        }

        return 'This password has been compromised in a data breach. Please choose a different password.';
    }
}
