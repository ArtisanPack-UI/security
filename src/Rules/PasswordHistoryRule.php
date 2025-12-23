<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\Rule;

class PasswordHistoryRule implements Rule
{
    /**
     * The user for history checking.
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
        if (! config('artisanpack.security.passwordSecurity.history.enabled', false)) {
            return true;
        }

        if ($this->user === null) {
            return true;
        }

        if (! method_exists($this->user, 'passwordExistsInHistory')) {
            return true;
        }

        return ! $this->user->passwordExistsInHistory($value);
    }

    /**
     * Get the validation error message.
     */
    public function message(): string
    {
        $count = config('artisanpack.security.passwordSecurity.history.count', 5);

        return "You cannot reuse any of your last {$count} passwords.";
    }
}
