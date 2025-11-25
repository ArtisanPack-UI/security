<?php

namespace Tests\Concerns;

use Illuminate\Support\Facades\Validator;

trait ValidatesInput
{
    /**
     * Assert that the given value passes the validation rule.
     *
     * @param \Illuminate\Contracts\Validation\Rule $rule
     * @param mixed $value
     * @return void
     */
    public function assertValidates($rule, $value)
    {
        $validator = Validator::make(['field' => $value], ['field' => $rule]);
        $this->assertTrue($validator->passes());
    }

    /**
     * Assert that the given value fails the validation rule.
     *
     * @param \Illuminate\Contracts\Validation\Rule $rule
     * @param mixed $value
     * @return void
     */
    public function assertFailsValidation($rule, $value)
    {
        $validator = Validator::make(['field' => $value], ['field' => $rule]);
        $this->assertTrue($validator->fails());
    }
}
