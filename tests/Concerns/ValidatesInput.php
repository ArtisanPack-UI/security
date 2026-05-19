<?php

declare(strict_types=1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\Validator;

trait ValidatesInput
{
    /**
     * Assert that the given value passes the validation rule.
     *
     * @param  \Illuminate\Contracts\Validation\Rule  $rule
     * @param  mixed  $value
     */
    public function assertValidates($rule, $value): void
    {
        $validator = Validator::make(['field' => $value], ['field' => $rule]);
        $this->assertTrue($validator->passes());
    }

    /**
     * Assert that the given value fails the validation rule.
     *
     * @param  \Illuminate\Contracts\Validation\Rule  $rule
     * @param  mixed  $value
     */
    public function assertFailsValidation($rule, $value): void
    {
        $validator = Validator::make(['field' => $value], ['field' => $rule]);
        $this->assertTrue($validator->fails());
    }
}
