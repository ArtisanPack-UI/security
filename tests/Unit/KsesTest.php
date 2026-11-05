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
    'base element' => ['<base href="https://evil.test/"><p>x</p>', '<base'],
    'form element' => ['<form action="https://evil.test/login"><p>Sign in</p></form>', '<form'],
    'input element' => ['<input type="password" name="pw">', '<input'],
    'button element' => ['<button type="submit">Go</button>', '<button'],
    'select element' => ['<select name="s"><optgroup label="g"><option>a</option></optgroup></select>', '<select'],
    'option element' => ['<select name="s"><option>a</option></select>', '<option'],
    'textarea element' => ['<textarea name="t">t</textarea>', '<textarea'],
    'frameset element' => ['<frameset><frame src="https://evil.test"></frameset>', '<frame'],
    'svg onload' => ['<svg onload="alert(1)"></svg>', 'onload'],
    'onclick handler' => ['<p onclick="x()">Hi</p>', 'onclick'],
    'onerror handler' => ['<img src=x onerror=alert(1)>', 'onerror'],
    'uppercase handler' => ['<p ONMOUSEOVER="x()">Hi</p>', 'onmouseover'],
    'style attribute' => ['<p style="background:url(javascript:alert(1))">s</p>', 'style='],
    'ping attribute' => ['<a href="https://example.com" ping="https://evil.test/track">x</a>', 'ping='],
    'custom element alpine init' => ['<x-a x-data x-init="alert(document.domain)">hi</x-a>', 'x-init'],
    'custom element alpine click' => ['<my-el @click="alert(1)" x-on:mouseover="alert(2)">hi</my-el>', '@click'],
    'custom element livewire action' => ['<my-el wire:click="delete(1)">hi</my-el>', 'wire:click'],
    'custom element bound href' => ['<a-b x-bind:href="\'javascript:alert(1)\'">hi</a-b>', 'x-bind'],
    'class attribute' => ['<div class="fixed inset-0 z-50 bg-white">x</div>', 'class='],
    'standard element alpine directives' => ['<div x-data x-init="alert(1)" @click="x()" wire:click="y()">d</div>', 'x-init'],
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
    'blockquote cite' => ['<blockquote cite="javascript:x()">q</blockquote>', 'cite'],
    'data img src' => ['<img src="data:image/svg+xml;base64,PHN2Zz4=" alt="a">', 'src'],
    'javascript img src' => ['<img src="javascript:alert(1)" alt="a">', 'src'],
    'srcset candidate' => ['<img src="a.jpg" srcset="a.jpg 1x, javascript:alert(1) 2x" alt="a">', 'srcset'],
]);

test('the default config reproduces the issue payload safely', function (): void {
    $html = '<p onclick="x()">Hi <a href="javascript:alert(1)">x</a></p><script>alert(1)</script><img src=x onerror=alert(1)>';

    expect(kses($html))->toBe('<p>Hi <a href="denied:javascript:alert(1)">x</a></p>alert(1)<img src="x" alt="image" />');
});

test('the default config only allows http and https URLs, plus mailto and tel links', function (): void {
    expect(kses('<a href="mailto:a@example.com">m</a><a href="tel:+15551234">t</a><a href="ftp://example.com">f</a><a href="file:///etc/passwd">l</a>'))
        ->toBe('<a href="mailto:a@example.com">m</a><a href="tel:+15551234">t</a><a href="denied:ftp://example.com">f</a><a href="denied:file:///etc/passwd">l</a>')
        ->and(kses('<img src="mailto:a@example.com" alt="a"><img src="https://example.com/a.jpg" alt="b">'))
        ->toBe('<img src="denied:mailto:a@example.com" alt="a" /><img src="https://example.com/a.jpg" alt="b" />');
});

test('the default config keeps relative and fragment URLs', function (): void {
    expect(kses('<a href="/products/linen">r</a><a href="#details">h</a><img src="images/a.jpg" alt="a">'))
        ->toBe('<a href="/products/linen">r</a><a href="#user-content-details">h</a><img src="images/a.jpg" alt="a" />');
});

test('the default config reproduces the full-strip issue payload safely', function (): void {
    $html = '<p>Soft linen.</p><script>alert(1)</script><img src=x onerror=alert(1)><a href="javascript:x">l</a>'
        .'<style>body{display:none}</style><link rel="stylesheet" href="https://evil.test/x.css">'
        .'<form action="https://evil.test"><input type="password" name="pw"><button>Log in</button></form>';

    expect(kses($html))->toBe('<p>Soft linen.</p>alert(1)<img src="x" alt="image" /><a href="denied:javascript:x">l</a>body{display:none}Log in');
});

test('the default config keeps ordinary formatting markup', function (): void {
    $html = '<p>Hello <strong>bold</strong> <em>ital</em> <a href="https://example.com" title="Example">link</a></p>'
        .'<h2>Heading</h2><h3>Sub</h3><ul><li>one</li></ul><ol><li>two</li></ol>'
        .'<img src="/a.jpg" alt="An image" srcset="/a.jpg 1x, /a@2x.jpg 2x">';

    expect(kses($html))->toBe(
        '<p>Hello <strong>bold</strong> <em>ital</em> <a href="https://example.com" title="Example">link</a></p>'
        .'<h2>Heading</h2><h3>Sub</h3><ul><li>one</li></ul><ol><li>two</li></ol>'
        .'<img src="/a.jpg" alt="An image" srcset="/a.jpg 1x, /a@2x.jpg 2x" />'
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

test('a spec cannot re-enable on*, style or class attributes under the default config', function (mixed $spec): void {
    $output = kses('<p onclick="x()" onmouseover="y()" style="color:red" class="fixed" title="t">x</p>', 1, $spec);

    expect($output)->toBe('<p title="t">x</p>');
})->with([
    'string spec' => ['p=onclick,onmouseover,style,class,title'],
    'wildcard string spec' => ['p=on*,style,class,title'],
    'array spec' => [['p' => ['onclick' => 1, 'ONMOUSEOVER' => 1, 'Style' => 1, 'Class' => 1, 'title' => 1]]],
]);

test('a spec cannot re-enable ping under the default config', function (): void {
    expect(kses('<a href="https://example.com" ping="https://evil.test">x</a>', 1, 'a=href,ping'))
        ->toBe('<a href="https://example.com">x</a>');
});

test('a spec cannot re-enable Alpine or Livewire directives under the default config', function (mixed $spec): void {
    expect(kses('<div x-init="alert(1)" title="t">d</div>', 1, $spec))->toBe('<div title="t">d</div>');
})->with([
    'string spec' => ['div=x-init,title'],
    'array spec' => [['div' => ['x-init' => 1, '@click' => 1, 'wire:click' => 1, ':class' => 1, 'is' => 1, 'title' => 1]]],
]);

test('the default config removes rel opener and adds noopener to targeted links', function (string $html, string $expected): void {
    expect(kses($html))->toBe($expected);
})->with([
    'opener with target' => ['<a href="https://example.com" target="_blank" rel="opener">x</a>', '<a href="https://example.com" target="_blank" rel="noopener">x</a>'],
    'opener among other link types' => ['<a href="https://example.com" target="_blank" rel="nofollow OPENER">x</a>', '<a href="https://example.com" target="_blank" rel="nofollow noopener">x</a>'],
    'target without rel' => ['<a href="https://example.com" target="_blank">x</a>', '<a href="https://example.com" target="_blank" rel="noopener">x</a>'],
    'existing noopener kept once' => ['<a href="https://example.com" target="_blank" rel="noopener noreferrer">x</a>', '<a href="https://example.com" target="_blank" rel="noopener noreferrer">x</a>'],
    'opener without target' => ['<a href="https://example.com" rel="opener">x</a>', '<a href="https://example.com">x</a>'],
    'other rel without target' => ['<a href="https://example.com" rel="nofollow">x</a>', '<a href="https://example.com" rel="nofollow">x</a>'],
]);

test('the default config prefixes ids and names to prevent DOM clobbering', function (): void {
    expect(kses('<h2 id="intro">I</h2><img name="config" src="a.jpg" alt="a">'))
        ->toBe('<h2 id="user-content-intro">I</h2><img src="a.jpg" alt="a" id="user-content-config" />');
});

test('the default config rewrites id references so in-page links keep working', function (): void {
    expect(kses('<a href="#intro">j</a><a href="#">top</a><a href="https://example.com/#intro">e</a>'))
        ->toBe('<a href="#user-content-intro">j</a><a href="#">top</a><a href="https://example.com/#intro">e</a>')
        ->and(kses('<div aria-labelledby="h1 h2" aria-describedby="d">x</div><table><tr><th id="c">C</th><td headers="c">1</td></tr></table>'))
        ->toBe('<div aria-labelledby="user-content-h1 user-content-h2" aria-describedby="user-content-d">x</div><table><tr><th id="user-content-c">C</th><td headers="user-content-c">1</td></tr></table>')
        ->and(kses('<img src="a.jpg" alt="a" usemap="#m"><map name="m"><area href="#intro" alt="x" shape="rect" coords="0,0,1,1"></map>'))
        ->toBe('<img src="a.jpg" alt="a" usemap="#user-content-m" /><map name="user-content-m" id="user-content-m"><area href="#user-content-intro" alt="x" shape="rect" coords="0,0,1,1" /></map>');
});

test('the default config output is stable when sanitized again', function (): void {
    $once = kses('<h2 id="a">x</h2><a href="#a" target="_blank" rel="opener">y</a><td headers="a">z</td><img src="a.jpg" alt="a"><br>');

    expect(kses($once))->toBe($once);
});

test('the safe tag hook keeps other attributes and closes void elements', function (): void {
    expect(Security::ksesSafeTag('p', ['title' => 't', 'lang' => 'en']))->toBe('<p title="t" lang="en">')
        ->and(Security::ksesSafeTag('br', []))->toBe('<br />')
        ->and(Security::ksesSafeTag('p'))->toBe('</p>');
});

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

test('the allowed tags filter cannot re-enable forms, form controls or base', function (string $tag, string $html): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => ['p', $tag]);

    expect(kses($html.'<p>p</p>'))->not->toContain('<'.$tag)
        ->and(kses($html.'<p>p</p>'))->toContain('<p>p</p>');
})->with([
    'base' => ['base', '<base href="https://evil.test/">'],
    'form' => ['form', '<form action="https://evil.test"></form>'],
    'input' => ['input', '<input type="password" name="pw">'],
    'button' => ['button', '<button>Go</button>'],
    'select' => ['select', '<select><option>a</option></select>'],
    'option' => ['option', '<option>a</option>'],
    'textarea' => ['textarea', '<textarea>t</textarea>'],
    'frame' => ['frame', '<frame src="https://evil.test">'],
]);

test('the allowed tags filter cannot re-enable custom elements', function (): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => ['p', 'x-a', 'evil-form']);

    expect(kses('<p>p</p><x-a x-data x-init="alert(1)">c</x-a><evil-form action="x">e</evil-form>'))
        ->toBe('<p>p</p>ce');
});

test('the default config drops custom elements but keeps their text', function (): void {
    expect(kses('<p>a</p><product-card data-id="1">Linen</product-card>'))->toBe('<p>a</p>Linen');
});

test('the allowed tags filter keeps the safe URL schemes', function (): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => ['a']);

    expect(kses('<a href="ftp://example.com">f</a><a href="mailto:a@example.com">m</a>'))
        ->toBe('<a href="denied:ftp://example.com">f</a><a href="mailto:a@example.com">m</a>');
});

test('the allowed tags filter keeps valid names after dropping invalid ones', function (): void {
    addFilter('ap.security.ksesAllowedTags', fn (array $allowedTags): array => [' P ', 'strong', '*', 'link']);

    expect(kses('<p>p</p><strong>s</strong><em>e</em>'))->toBe('<p>p</p><strong>s</strong>e');
});

test('the default config strips every element the allowed tags guard blocks', function (): void {
    $unsafeElements = (new ReflectionClassConstant(Security::class, 'KSES_UNSAFE_ELEMENTS'))->getValue();

    foreach ($unsafeElements as $element) {
        expect(kses('<'.$element.' title="t">x</'.$element.'><p>p</p>'))
            ->not->toContain('<'.$element.' ')
            ->not->toContain('<'.$element.'>')
            ->toContain('<p>p</p>');
    }
});

test('the safe config constant is exposed for callers that want to extend it', function (): void {
    expect(Security::KSES_SAFE_CONFIG)->toMatchArray([
        'safe' => 1,
        'elements' => '*-base-button-datalist-form-frame-frameset-input-isindex-keygen-link-meta-optgroup-option-select-style-textarea',
        'deny_attribute' => 'on*, class, ping, style',
        'any_custom_element' => 0,
        'schemes' => 'href: http, https, mailto, tel; src: http, https; *: http, https',
        'hook_tag' => [Security::class, 'ksesSafeTag'],
    ]);
});
