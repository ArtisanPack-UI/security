<?php

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Validation\Rule;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;

class PasswordPolicy implements Rule
{
    /**
     * The validation errors.
     *
     * @var array
     */
    protected $errors = [];

    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     * @return bool
     */
    public function passes($attribute, $value)
    {
        $validator = Validator::make(['password' => $value], [
            'password' => [
                'required',
                Password::min(8)
                    ->letters()
                    ->mixedCase()
                    ->numbers()
                    ->symbols()
                    ->uncompromised(),
            ],
        ]);

        if ($validator->fails()) {
            $this->errors = $validator->errors()->all();
            return false;
        }

        return true;
    }

    /**
     * Get the validation error message.
     *
     * @return array
     */
    public function message()
    {
        return $this->errors;
    }
}
