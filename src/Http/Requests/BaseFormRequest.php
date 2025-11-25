<?php

namespace ArtisanPackUI\Security\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Log;

class BaseFormRequest extends FormRequest
{
    /**
     * The sanitization rules to be applied to the request data.
     *
     * @var array
     */
    protected $sanitizationRules = [];

    /**
     * Get the validated data from the request.
     *
     * @return array
     */
    public function validated($key = null, $default = null)
    {
        $validatedData = parent::validated();

        return $this->sanitize($validatedData);
    }

    /**
     * Sanitize the given data based on the defined rules.
     *
     * @param array $data
     * @return array
     */
    protected function sanitize(array $data): array
    {
        foreach ($data as $key => &$value) {
            if (is_string($value)) {
                $rule = $this->sanitizationRules[$key] ?? 'text';
                $value = $this->applySanitizationRule($rule, $value);
            }
        }

        return $data;
    }

    /**
     * Apply the given sanitization rule to the value.
     *
     * @param string $rule
     * @param string $value
     * @return string
     */
    protected function applySanitizationRule(string $rule, string $value): string
    {
        return match ($rule) {
            'html' => kses($value),
            'email' => sanitizeEmail($value),
            'url' => sanitizeUrl($value),
            'filename' => sanitizeFilename($value),
            'text' => sanitizeText($value),
            default => $this->handleUnknownRule($rule, $value),
        };
    }

    /**
     * Handle an unknown sanitization rule.
     *
     * @param string $rule
     * @param string $value
     * @return string
     */
    protected function handleUnknownRule(string $rule, string $value): string
    {
        Log::warning("Unknown sanitization rule '{$rule}' used in a FormRequest. Falling back to text sanitization.");
        return sanitizeText($value);
    }
}
