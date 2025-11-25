<?php

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Validation\Rule;

class SecureUrl implements Rule
{
    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     * @return bool
     */
    public function passes($attribute, $value)
    {
        if (!is_string($value)) {
            return false;
        }

        if (filter_var($value, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        $scheme = parse_url($value, PHP_URL_SCHEME);

        return in_array($scheme, ['http', 'https']);
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message()
    {
        return 'The :attribute must be a secure URL.';
    }
}
