<?php

/**
 * Security core class — sanitization, escaping, KSES.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security;

use Laminas\Escaper\Escaper;

use function ArtisanPackUI\Security\HTMLawed\htmLawed;

class Security
{
    /**
     * Returns a sanitized email string.
     *
     * @param  string|null  $email  The email to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeEmail(?string $email = ''): string
    {
        if ($email === null || $email === '') {
            return applyFilters('ap.security.sanitizedInput', '', 'email', $email);
        }

        return applyFilters(
            'ap.security.sanitizedInput',
            filter_var($email, FILTER_SANITIZE_EMAIL),
            'email',
            $email,
        );
    }

    /**
     * Returns a sanitized url string.
     *
     * @param  string|null  $url  The url to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeUrl(?string $url = ''): string
    {
        if ($url === null || $url === '') {
            return applyFilters('ap.security.sanitizedInput', '', 'url', $url);
        }

        return applyFilters(
            'ap.security.sanitizedInput',
            filter_var($url, FILTER_SANITIZE_URL),
            'url',
            $url,
        );
    }

    /**
     * Returns a sanitized filename.
     *
     * @param  string|null  $filename  The filename to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeFilename(?string $filename = ''): string
    {
        if ($filename === null || $filename === '') {
            return applyFilters('ap.security.sanitizedInput', '', 'filename', $filename);
        }

        return applyFilters(
            'ap.security.sanitizedInput',
            htmlspecialchars($filename, ENT_QUOTES, 'UTF-8'),
            'filename',
            $filename,
        );
    }

    /**
     * Returns a sanitized password.
     *
     * @param  string|null  $password  The password to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizePassword(?string $password = ''): string
    {
        if ($password === null || $password === '') {
            return applyFilters('ap.security.sanitizedInput', '', 'password', $password);
        }

        return applyFilters(
            'ap.security.sanitizedInput',
            htmlspecialchars($password, ENT_QUOTES, 'UTF-8'),
            'password',
            $password,
        );
    }

    /**
     * Returns a sanitized integer.
     *
     * @param  mixed  $integer  The integer to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeInt(mixed $integer = ''): int
    {
        return applyFilters(
            'ap.security.sanitizedInput',
            intval($integer),
            'int',
            $integer,
        );
    }

    /**
     * Returns a sanitized date string.
     *
     * @param  string|null  $date  The date to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeDate(?string $date = ''): string
    {
        if ($date === null || $date === '') {
            return applyFilters('ap.security.sanitizedInput', '', 'date', $date);
        }

        return applyFilters(
            'ap.security.sanitizedInput',
            date('Y-m-d', strtotime($date)),
            'date',
            $date,
        );
    }

    /**
     * Returns a sanitized datetime string.
     *
     * @param  string  $datetime  The datetime to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeDatetime(string $datetime = ''): string
    {
        return applyFilters(
            'ap.security.sanitizedInput',
            date('Y-m-d H:i:s', strtotime($datetime)),
            'datetime',
            $datetime,
        );
    }

    /**
     * Returns a sanitized float value.
     *
     * @param  float  $float  The number to sanitize.
     * @param  int  $decimals  The number of decimal places to round to.
     *
     * @since 1.0.0
     */
    public function sanitizeFloat(float $float, int $decimals = 2): float
    {
        return applyFilters(
            'ap.security.sanitizedInput',
            (float) number_format($float, $decimals, '.', ''),
            'float',
            $float,
        );
    }

    /**
     * Returns a sanitized array.
     *
     * @param  array  $options  The array to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeArray(array $options = []): array
    {
        $sanitized = array_map(function ($value) {
            return $this->sanitizeText($value);
        }, $options);

        return applyFilters(
            'ap.security.sanitizedInput',
            $sanitized,
            'array',
            $options,
        );
    }

    /**
     * Returns a sanitized version of the string.
     *
     * @param  string|null  $input  The string to sanitize.
     *
     * @since 1.0.0
     */
    public function sanitizeText(?string $input = ''): string
    {
        if ($input === null || $input === '') {
            return applyFilters('ap.security.sanitizedInput', '', 'text', $input);
        }

        return applyFilters(
            'ap.security.sanitizedInput',
            strip_tags($input),
            'text',
            $input,
        );
    }

    /**
     * Returns an escaped string of HTML.
     *
     * @param  string|null  $string  The string to escape.
     *
     * @since 1.0.0
     */
    public function escHtml(?string $string = ''): string
    {
        if ($string === null || $string === '') {
            return applyFilters('ap.security.escapedOutput', '', 'html', $string);
        }

        return applyFilters(
            'ap.security.escapedOutput',
            (new Escaper)->escapeHtml($string),
            'html',
            $string,
        );
    }

    /**
     * Returns an escaped string of HTML attributes.
     *
     * @param  string|null  $string  The string to escape.
     *
     * @since 1.0.0
     */
    public function escAttr(?string $string = ''): string
    {
        if ($string === null || $string === '') {
            return applyFilters('ap.security.escapedOutput', '', 'attr', $string);
        }

        return applyFilters(
            'ap.security.escapedOutput',
            (new Escaper)->escapeHtmlAttr($string),
            'attr',
            $string,
        );
    }

    /**
     * Returns an escaped URL string.
     *
     * @param  string|null  $string  The url to escape.
     *
     * @since 1.0.0
     */
    public function escUrl(?string $string = ''): string
    {
        if ($string === null || $string === '') {
            return applyFilters('ap.security.escapedOutput', '', 'url', $string);
        }

        return applyFilters(
            'ap.security.escapedOutput',
            (new Escaper)->escapeUrl($string),
            'url',
            $string,
        );
    }

    /**
     * Returns an escaped JavaScript string.
     *
     * @param  string|null  $string  The JavaScript to escape.
     *
     * @since 1.0.0
     */
    public function escJs(?string $string = ''): string
    {
        if ($string === null || $string === '') {
            return applyFilters('ap.security.escapedOutput', '', 'js', $string);
        }

        return applyFilters(
            'ap.security.escapedOutput',
            (new Escaper)->escapeJs($string),
            'js',
            $string,
        );
    }

    /**
     * Returns an escaped CSS string.
     *
     * @param  string|null  $string  The CSS to escape.
     *
     * @since 1.0.0
     */
    public function escCss(?string $string = ''): string
    {
        if ($string === null || $string === '') {
            return applyFilters('ap.security.escapedOutput', '', 'css', $string);
        }

        return applyFilters(
            'ap.security.escapedOutput',
            (new Escaper)->escapeCss($string),
            'css',
            $string,
        );
    }

    /**
     * Returns a secure string for content containing HTML markup.
     *
     * Fires the `ap.security.ksesAllowedTags` filter to let host apps
     * restrict which HTML elements survive the pass. Subscribers receive
     * an empty array and return the tags they want to allow (lowercase
     * element names, e.g. `['a', 'p', 'strong']`).
     *
     * The filter is only consulted when the caller uses the default
     * `$config = 1`; explicitly passing a different profile or a config
     * array signals caller intent that should not be silently
     * overridden by a global subscriber. When the filter returns a
     * non-empty list under the default config, it overrides htmLawed's
     * default element whitelist for this call.
     *
     * @param  string  $html  The HTML to clean.
     * @param  mixed  $config  Configuration options.
     * @param  mixed  $spec  Specification options.
     *
     * @since 1.0.0
     */
    public function kses(string $html, mixed $config = 1, mixed $spec = []): string
    {
        if ($config === 1) {
            $allowedTags = applyFilters('ap.security.ksesAllowedTags', []);

            if (is_array($allowedTags) && $allowedTags !== []) {
                $config = [
                    'elements' => implode(',', array_map('strtolower', $allowedTags)),
                ];
            }
        }

        return htmLawed($html, $config, $spec);
    }

    /**
     * Sanitizes an array of data based on the provided rules.
     */
    public function sanitize(array $data, array $rules): array
    {
        foreach ($data as $key => &$value) {
            if (is_string($value)) {
                $rule = $rules[$key] ?? 'text';
                $value = $this->applySanitizationRule($rule, $value);
            }
        }

        return $data;
    }

    /**
     * Apply the given sanitization rule to the value.
     */
    protected function applySanitizationRule(string $rule, string $value): string
    {
        return match ($rule) {
            'html' => $this->kses($value),
            'email' => $this->sanitizeEmail($value),
            'url' => $this->sanitizeUrl($value),
            'filename' => $this->sanitizeFilename($value),
            'text' => $this->sanitizeText($value),
            default => $this->sanitizeText($value),
        };
    }
}
