<?php

declare(strict_types=1);

use ArtisanPackUI\Security\Security;

if (! function_exists('security')) {
    /**
     * Get the Security instance.
     *
     * @return Security
     */
    function security()
    {
        return app('security');
    }
}

if (! function_exists('sanitizeEmail')) {
    function sanitizeEmail(?string $email = ''): string
    {
        return security()->sanitizeEmail($email);
    }
}

if (! function_exists('sanitizeUrl')) {
    function sanitizeUrl(?string $url = ''): string
    {
        return security()->sanitizeUrl($url);
    }
}

if (! function_exists('sanitizeFilename')) {
    function sanitizeFilename(?string $filename = ''): string
    {
        return security()->sanitizeFilename($filename);
    }
}

if (! function_exists('sanitizePassword')) {
    function sanitizePassword(?string $password = ''): string
    {
        return security()->sanitizePassword($password);
    }
}

if (! function_exists('sanitizeInt')) {
    function sanitizeInt(mixed $int = ''): int
    {
        return security()->sanitizeInt($int);
    }
}

if (! function_exists('sanitizeDate')) {
    function sanitizeDate(?string $date = ''): string
    {
        return security()->sanitizeDate($date);
    }
}

if (! function_exists('sanitizeDatetime')) {
    function sanitizeDatetime(?string $datetime = ''): string
    {
        return security()->sanitizeDatetime($datetime);
    }
}

if (! function_exists('sanitizeFloat')) {
    function sanitizeFloat(mixed $float = ''): int
    {
        return security()->sanitizeFloat($float);
    }
}

if (! function_exists('sanitizeArray')) {
    function sanitizeArray(array $array): array
    {
        return security()->sanitizeArray($array);
    }
}

if (! function_exists('sanitizeText')) {
    function sanitizeText(?string $text = ''): string
    {
        return security()->sanitizeText($text);
    }
}

if (! function_exists('escHtml')) {
    function escHtml(?string $string = ''): string
    {
        return security()->escHtml($string);
    }
}

if (! function_exists('escAttr')) {
    function escAttr(?string $string = ''): string
    {
        return security()->escAttr($string);
    }
}

if (! function_exists('escUrl')) {
    function escUrl(?string $string = ''): string
    {
        return security()->escUrl($string);
    }
}

if (! function_exists('escJs')) {
    function escJs(?string $string = ''): string
    {
        return security()->escJs($string);
    }
}

if (! function_exists('escCss')) {
    function escCss(?string $string = ''): string
    {
        return security()->escCss($string);
    }
}

if (! function_exists('kses')) {
    function kses(?string $string = ''): string
    {
        return security()->kses($string);
    }
}

if (! function_exists('sanitize')) {
    function sanitize(array $data, array $rules): array
    {
        return security()->sanitize($data, $rules);
    }
}
