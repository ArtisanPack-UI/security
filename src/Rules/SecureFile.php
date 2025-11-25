<?php

namespace ArtisanPackUI\Security\Rules;

use Illuminate\Contracts\Validation\Rule;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Validator;

class SecureFile implements Rule
{
    /**
     * @var array
     */
    protected $allowedMimeTypes = [];

    /**
     * @var int
     */
    protected $maxSize = 2048; // 2MB

    /**
     * @var array
     */
    protected $errors = [];

    public function __construct(array $allowedMimeTypes = [], int $maxSize = null)
    {
        $this->allowedMimeTypes = $allowedMimeTypes;
        if ($maxSize !== null) {
            $this->maxSize = $maxSize;
        }
    }

    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     * @return bool
     */
    public function passes($attribute, $value)
    {
        if (!$value instanceof UploadedFile) {
            $this->errors[] = 'The :attribute must be a file.';
            return false;
        }

        if ($value->getSize() > $this->maxSize * 1024) {
            $this->errors[] = "The :attribute may not be greater than {$this->maxSize} kilobytes.";
            return false;
        }

        if (!empty($this->allowedMimeTypes) && !in_array($value->getMimeType(), $this->allowedMimeTypes)) {
            $this->errors[] = 'The :attribute must be a file of type: ' . implode(', ', $this->allowedMimeTypes);
            return false;
        }

        return true;
    }

    /**
     * Get the validation error message.
     *
     * @return array|string
     */
    public function message()
    {
        return $this->errors;
    }
}
