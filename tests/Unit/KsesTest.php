<?php

/**
 * Coverage for the default (safe) and caller-supplied kses() configs.
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.2.0
 */

declare(strict_types=1);

use ArtisanPackUI\Security\Security;

afterEach(function (): void {
    removeAllFilters('ap.security.ksesAllowedTags');
});

test('the default config strips executable markup', function (string $html, string $forbidden): void {
    expect(kses($html))->not->toContain($forbidden)
        ->and(security()->kses($html))->not->toContain($forbidden);
})->with([
    'script element' => ['<p>Hi</p><script>alert(1)</script>', '<script'],
    'iframe element' => ['<iframe src="https://evil.test"></iframe>', '<iframe'],
    'object element' => ['<object data="evil.swf"></object>', '<object'],
    'embed element' => ['<embed src="evil.swf">', '<embed'],
    'style element' => ['<style>body{display:none}</style><p>x</p>', '<style'],
    'link element' => ['<link rel="stylesheet" href="https://evil.test/x.css"><p>x</p>', '<link'],
    'meta element' => ['<meta http-equiv="refresh" content="0;url=https://evil.test"><p>x</p>', '<meta'],
    'svg onload' => ['<svg onload="alert(1)"></svg>', 'onload'],
    'onclick handler' => ['<p onclick="x()">Hi</p>', 'onclick'],
    'onerror handler' => ['<img src=x onerror=alert(1)>', 'onerror'],
    'uppercase handler' => ['<p ONMOUSEOVER="x()">Hi</p>', 'onmouseover'],
    'style attribute' => ['<p style="background:url(javascript:alert(1))">s</p>', 'style='],
]);

test('the default config neutralizes executable URLs', function (string $html, string $attribute): void {
    $output = kses($html);

    expect($output)->toMatch('/'.$attribute.'="[^"]*denied:/')
        ->and($output)->not->toMatch('/(?<!denied:)(javascript|data):/i');
})->with([
    'javascript href' => ['<a href="javascript:alert(1)">x</a>', 'href'],
    'mixed case href' => ['<a href="JaVaScRiPt:alert(1)">x</a>', 'href'],
    'entity encoded href' => ['<a href="&#106;avascript:alert(1)">x</a>', 'href'],
    'data href' => ['<a href="data:text/html,x">x</a>', 'href'],
    'form action' => ['<form action="javascript:x()"><p>f</p></form>', 'action'],
    'srcset candidate' => ['<img src="a.jpg" srcset="a.jpg 1x, javascript:alert(1) 2x" alt="a">', 'srcset'],
]);

test('the default config reproduces the issue payload safely', function (): void {
    $html = '<p onclick="x()">Hi <a href="javascript:alert(1)">x</a></p><script>alert(1)</script><img src=x onerror=alert(1)>';

    expect(kses($html))->toBe('<p>Hi <a href="denied:javascript:alert(1)">x</a></p>alert(1)<img src="x" alt="image" />');
});

test('the default config keeps ordinary formatting markup', function (): void {
    $html = '<p class="lead">Hello <strong>bold</strong> <em>ital</em> <a href="https://example.com" title="Example">link</a></p>'
        .'<ul><li>one</li></ul><img src="/a.jpg" alt="An image" srcset="/a.jpg 1x, /a@2x.jpg 2x">';

    expect(kses($html))->toBe(
        '<p class="lead">Hello <strong>bold</strong> <em>ital</em> <a href="https://example.com" title="Example">link</a></p>'
        .'<ul><li>one</li></ul><img src="/a.jpg" alt="An image" srcset="/a.jpg 1x, /a@2x.jpg 2x" />'
    );
});

test('the kses helper forwards config and spec to Security::kses', function (): void {
    expect(kses('<p>Hi</p><b>x</b>', ['elements' => 'b']))->toBe('Hi<b>x</b>')
        ->and(kses('<b title="t" id="i">x</b>', 1, 'b=-id'))->toBe('<b title="t">x</b>');
});

test('quoted spec rule values keep their separator characters', function (): void {
    $spec = 'b=title(oneof="a; b|c, d")';

    expect(kses('<b title="a; b">x</b>', 1, $spec))->toBe('<b title="a; b">x</b>')
        ->and(kses('<b title="c, d">x</b>', 1, $spec))->toBe('<b title="c, d">x</b>')
        ->and(kses('<b title="a">x</b>', 1, $spec))->toBe('<b>x</b>');
});

test('a spec cannot re-enable on* or style attributes under the default config', function (mixed $spec): void {
    $output = kses('<p onclick="x()" onmouseover="y()" style="color:red" title="t">x</p>', 1, $spec);

    expect($output)->toBe('<p title="t">x</p>');
})->with([
    'string spec' => ['p=onclick,onmouseover,style,title'],
    'wildcard string spec' => ['p=on*,style,title'],
    'array spec' => [['p' => ['onclick' => 1, 'ONMOUSEOVER' => 1, 'Style' => 1, 'title' => 1]]],
]);

test('a spec default cannot inject an executable URL', function (): void {
    expect(kses('<a href="">x</a>', 1, 'a=href(default="javascript:alert(1)")'))
        ->toBe('<a href="denied:javascript:alert(1)">x</a>')
        ->and(kses('<a href="">x</a>', 1, 'a=href(default="https://example.com")'))
        ->toBe('<a href="https://example.com">x</a>');
});

test('an explicit config still lets a spec permit on* attributes', function (): void {
    expect(kses('<p onclick="x()">x</p>', ['elements' => 'p'], 'p=onclick'))->toBe('<p onclick="x()">x</p>');
});

test('deprecated markup does not generate style attributes under the default config', function (): void {
    expect(kses('<center>c</center><font color="red">f</font><img src="a.jpg" align="left" alt="a"><table><tr><td bgcolor="red">t</td></tr></table>'))
        ->toBe('<div>c</div><span>f</span><img src="a.jpg" alt="a" /><table><tr><td>t</td></tr></table>');
});

test('deprecated markup still converts to style when style is allowed', function (): void {
    expect(kses('<center>c</center>', ['safe' => 1]))->toBe('<div style="text-align: center;">c</div>');
});

test('srcset candidates are converted once when abs_url is set', function (): void {
    $config = ['base_url' => 'https://example.com/media/'];

    expect(kses('<img src="a.jpg" srcset="a.jpg 1x, b.jpg 2x" alt="a">', $config + ['abs_url' => 1]))
        ->toBe('<img src="https://example.com/media/a.jpg" srcset="https://example.com/media/a.jpg 1x, https://example.com/media/b.jpg 2x" alt="a" />')
        ->and(kses('<img src="https://example.com/media/a.jpg" srcset="https://example.com/media/a.jpg 1x, https://example.com/media/b.jpg 2x" alt="a">', $config + ['abs_url' => -1]))
        ->toBe('<img src="a.jpg" srcset="a.jpg 1x, b.jpg 2x" alt="a" />');
});

test('the kses helper returns an empty string for null input', function (): void {
    expect(kses(null))->toBe('');
});

test('an explicit config is passed through unchanged', function (): void {
    expect(kses('<p onclick="x()">Hi</p>', ['elements' => 'p']))->toBe('<p onclick="x()">Hi</p>');
});

test('explicit safe mode no longer crashes on style attributes', function (): void {
    expect(kses('<p style="background:url(javascript:alert(1))">s</p>', ['safe' => 1]))
        ->toBe('<p style="background:url(denied:javascript:alert(1))">s</p>');
});

test('the allowed tags filter keeps the safe rules', function (): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => ['a', 'script']);

    expect(kses('<a href="javascript:x()" onclick="y()">a</a><script>alert(1)</script><p>p</p>'))
        ->toBe('<a href="denied:javascript:x()">a</a>alert(1)p');
});

test('a filter listing only unsafe tags strips every element', function (): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => ['script', 'style']);

    expect(kses('<p>p</p><script>alert(1)</script><style>b{}</style>'))->toBe('palert(1)b{}');
});

test('the allowed tags filter cannot smuggle unsafe elements past the guard', function (array $tags): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => $tags);

    $output = kses('<p>p</p><script>alert(1)</script><style>b{}</style><link rel="stylesheet" href="x.css">');

    expect($output)->not->toContain('<script')
        ->and($output)->not->toContain('<style')
        ->and($output)->not->toContain('<link');
})->with([
    'padded name' => [['p', ' script ']],
    'uppercase name' => [['p', 'SCRIPT', 'Style']],
    'wildcard' => [['*']],
    'htmLawed operators' => [['*+script', 'p+style']],
    'comma list in one entry' => [['p,script']],
    'non-string entries' => [['p', 1, null, ['script']]],
]);

test('the allowed tags filter keeps valid names after dropping invalid ones', function (): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => [' P ', 'strong', '*', 'link']);

    expect(kses('<p>p</p><strong>s</strong><em>e</em>'))->toBe('<p>p</p><strong>s</strong>e');
});

test('the safe config constant is exposed for callers that want to extend it', function (): void {
    expect(Security::KSES_SAFE_CONFIG)->toMatchArray([
        'safe' => 1,
        'elements' => '*-link-meta-style',
        'deny_attribute' => 'on*, style',
    ]);
});
