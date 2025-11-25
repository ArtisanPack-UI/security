<?php

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Validation\Rule;

class NoHtml implements Rule
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
            return true;
        }

        return strip_tags($value) === $value;
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message()
    {
        return 'The :attribute must not contain HTML.';
    }
}
