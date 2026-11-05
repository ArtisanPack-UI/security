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

use function ArtisanPackUI\Security\HTMLawed\hl_spec;
use function ArtisanPackUI\Security\HTMLawed\htmLawed;

class Security
{
    /**
     * The htmLawed config `kses()` uses when the caller passes the default `$config = 1`.
     *
     * Safe mode drops script-capable elements (script, iframe, object, embed,
     * applet, ...) and neutralizes `javascript:`/`data:` URLs by prefixing them
     * with `denied:`. On top of that:
     *
     * - Elements that can restyle or hijack the page are removed: `<style>`,
     *   `<link>`, `<meta>`, `<base>`, forms and form controls, and frames.
     * - Every `on*`, `style` and `ping` attribute is removed.
     * - Custom (hyphenated) elements are removed, because htmLawed lets them
     *   keep every attribute, including Alpine/Livewire directives such as
     *   `x-init`.
     * - URLs are limited to `http`/`https` (plus `mailto`/`tel` for `href`).
     *   Relative URLs are kept.
     *
     * The output can therefore be printed unescaped.
     *
     * @since 2.2.0
     *
     * @var array<string, int|string>
     */
    public const KSES_SAFE_CONFIG = [
        'safe' => 1,
        'elements' => '*-base-button-datalist-form-frame-frameset-input-isindex-keygen-link-meta-optgroup-option-select-style-textarea',
        'deny_attribute' => 'on*, ping, style',
        'any_custom_element' => 0,
        'schemes' => 'href: http, https, mailto, tel; src: http, https; *: http, https',
    ];

    /**
     * Elements `kses()` never lets through under the default config, even
     * when an `ap.security.ksesAllowedTags` subscriber lists them.
     *
     * htmLawed applies an explicit element list verbatim, bypassing safe
     * mode's own element removal, so these are subtracted before the list
     * is handed over. `<link>`, `<meta>`, `<style>` and `<base>` are included
     * because they allow CSS injection or page-level side effects, and forms,
     * form controls and frames because they allow fake login forms and
     * framing on the site's own origin.
     *
     * @since 2.2.0
     *
     * @var list<string>
     */
    protected const KSES_UNSAFE_ELEMENTS = [
        'applet', 'audio', 'base', 'button', 'canvas', 'datalist', 'dialog', 'embed', 'form', 'frame', 'frameset',
        'iframe', 'input', 'isindex', 'keygen', 'link', 'meta', 'object', 'optgroup', 'option', 'script', 'select',
        'style', 'textarea', 'video',
    ];

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
     * With the default `$config = 1` the HTML is filtered with
     * {@see self::KSES_SAFE_CONFIG}: script-capable elements, `<style>`,
     * `<link>`, `<meta>`, `<base>`, forms, form controls and frames, `on*`
     * event handlers, `ping` and `style` attributes and custom elements are
     * removed, and URLs with any
     * scheme other than `http`/`https` (plus `mailto`/`tel` in `href`) are
     * rewritten to `denied:<url>`, so the result is safe to print unescaped. Under the default config `$spec`
     * cannot re-enable `on*` or `style` attributes; those entries are dropped
     * before it reaches htmLawed. Passing any other `$config` hands full
     * control to the caller, and `$config` and `$spec` are forwarded as-is.
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
     * non-empty list under the default config, it replaces the element
     * whitelist for this call; the {@see self::KSES_UNSAFE_ELEMENTS} are still
     * dropped from that list, and the attribute and URL rules still apply.
     *
     * @param  string  $html  The HTML to clean.
     * @param  mixed  $config  htmLawed configuration, or `1` for the safe default.
     * @param  mixed  $spec  htmLawed attribute specification.
     *
     * @since 1.0.0
     * @since 2.2.0 The default config filters executable markup.
     */
    public function kses(string $html, mixed $config = 1, mixed $spec = []): string
    {
        if ($config === 1) {
            $config = self::KSES_SAFE_CONFIG;
            $allowedTags = applyFilters('ap.security.ksesAllowedTags', []);

            if (is_array($allowedTags) && $allowedTags !== []) {
                $config['elements'] = $this->ksesElementList($allowedTags);
            }

            $spec = $this->ksesSafeSpec($spec);
        }

        return htmLawed($html, $config, $spec);
    }

    /**
     * Builds a safe htmLawed `elements` list from `ksesAllowedTags` output.
     *
     * Each entry is trimmed and lowercased. Anything that isn't a plain element
     * name is dropped (wildcards, htmLawed `+`/`-` operators, whitespace
     * tricks, non-strings), and so are the {@see self::KSES_UNSAFE_ELEMENTS}.
     * Custom (hyphenated) element names are dropped too: htmLawed lets a listed
     * custom element keep every attribute, including Alpine/Livewire directives.
     * When nothing survives, every element is stripped.
     *
     * @param  array<int|string, mixed>  $allowedTags  Tags returned by the filter.
     *
     * @since 2.2.0
     */
    protected function ksesElementList(array $allowedTags): string
    {
        $safeTags = [];

        foreach ($allowedTags as $tag) {
            if (! is_string($tag)) {
                continue;
            }

            $tag = strtolower(trim($tag));

            if (preg_match('/^[a-z][a-z0-9]*$/', $tag) === 1 && ! in_array($tag, self::KSES_UNSAFE_ELEMENTS, true)) {
                $safeTags[$tag] = $tag;
            }
        }

        return $safeTags === [] ? '-*' : implode(',', $safeTags);
    }

    /**
     * Removes `on*` and `style` permissions from an htmLawed `$spec`.
     *
     * htmLawed lets `$spec` permit attributes that `deny_attribute` denies, so
     * under the default config those entries would undo the safe rules. A
     * string spec is parsed with htmLawed's own parser first. Element-level
     * `deny` rules and every other attribute rule are kept.
     *
     * @param  mixed  $spec  The caller's htmLawed spec (string or parsed array).
     * @return array<string, mixed> The parsed spec without `on*`/`style` entries.
     *
     * @since 2.2.0
     */
    protected function ksesSafeSpec(mixed $spec): array
    {
        if (is_string($spec)) {
            $spec = trim($spec) === '' ? [] : hl_spec($spec);
        }

        if (! is_array($spec)) {
            return [];
        }

        foreach ($spec as $element => $rules) {
            if (! is_array($rules)) {
                continue;
            }

            foreach (array_keys($rules) as $attribute) {
                $name = strtolower((string) $attribute);

                if ($name === 'style' || str_starts_with($name, 'on')) {
                    unset($spec[$element][$attribute]);
                }
            }
        }

        return $spec;
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
