---
title: HTML Filtering (kses)
---

# HTML Filtering (kses)

`kses()` cleans user-supplied HTML so rich content (comments, bios, post bodies) can be stored and printed without opening the page to XSS. It is built on a bundled, namespaced copy of [htmLawed](https://www.bioinformatics.org/phplabware/internal_utilities/htmLawed/).

```php
use ArtisanPackUI\Security\Facades\Security;

$clean = kses( $request->input( 'body' ) );
$clean = Security::kses( $request->input( 'body' ) );
```

```blade
{!! kses( $post->body ) !!}
```

## The safe default

Since 2.2.0, calling `kses()` without a `$config` (or with `$config = 1`) applies `Security::KSES_SAFE_CONFIG`. Output produced under the default config is safe to print unescaped.

The default config:

| Rule | Effect |
|---|---|
| htmLawed safe mode | Removes `<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>` and other executable elements. The text inside them is kept as escaped text. |
| Page-hijacking elements removed | `<style>`, `<link>`, `<meta>`, `<base>`, `<form>` and form controls (`<input>`, `<button>`, `<select>`, `<option>`, `<optgroup>`, `<textarea>`, `<datalist>`, `<keygen>`, `<isindex>`), and frames (`<frame>`, `<frameset>`). |
| Denied attributes | Every `on*` event handler, plus `style`, `class` and `ping`. |
| Directive attributes removed | Alpine and Livewire attributes (`x-*`, `@*`, `:*`, `wire:*`) and `is`, on every element. |
| Custom elements removed | Hyphenated elements such as `<x-alert>` are dropped (their text is kept). |
| URL schemes | `href` allows `http`, `https`, `mailto` and `tel`; every other URL attribute allows `http` and `https`. Any other scheme (`javascript:`, `data:`, `ftp:`, `file:`, …) is rewritten to `denied:…`. Relative and `#fragment` URLs are kept. |
| Reverse tabnabbing | `rel="opener"` is removed, and `noopener` is added to links with a `target`. |
| DOM clobbering | `id` and `name` values are prefixed with `Security::KSES_ID_PREFIX` (`user-content-`). `#fragment` links and ID references (`for`, `headers`, `usemap`, `list`, `itemref`, `aria-labelledby`, `aria-describedby`, `aria-controls`, …) are rewritten to match, so in-page links keep working. Values that already carry the prefix are left alone. IDs stay unique within each call after prefixing: a repeated `id` (or one containing whitespace) is dropped. |

```php
kses( '<div class="x" id="intro"><p onclick="steal()">Hi <a href="javascript:alert(1)">x</a> <a href="#intro" target="_blank">top</a></p><script>alert(1)</script></div>' );
// <div id="user-content-intro"><p>Hi <a href="denied:javascript:alert(1)">x</a> <a href="#user-content-intro" target="_blank" rel="noopener">top</a></p>alert(1)</div>
```

Sanitizing output that has already been through `kses()` gives the same result, so it is safe to run on both write and read. ID uniqueness is checked per call, so separate `kses()` calls (for example, one per comment) each keep their IDs. If you print several sanitized fragments on one page, an `id` repeated across them can still appear twice.

### Where the default applies

The same safe default is used by:

- the global `kses()` helper and `Security::kses()`;
- `Security::sanitize()` and `BaseFormRequest` for fields using the `html` rule;
- the opt-in `XssProtection` middleware, which skips the input keys in `artisanpack.security.xss.except` (`password`, `password_confirmation` and `current_password` by default) so credentials reach the hasher unchanged.

## Narrowing allowed elements

Use the `ap.security.ksesAllowedTags` filter to limit which elements survive the default config across the whole app. Return a list of lowercase element names; everything else is stripped (its text is kept).

```php
addFilter( 'ap.security.ksesAllowedTags', function ( array $allowedTags ): array {
    return [ 'a', 'p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre' ];
} );
```

The filter can only narrow the safe default:

- It runs only when the caller uses the default config. An explicit `$config` bypasses it.
- `script`, `style`, `link`, `meta`, `base`, `iframe`, `frame`, `frameset`, `object`, `embed`, `applet`, `audio`, `video`, `canvas`, `dialog`, forms and form controls are always removed from the returned list.
- Entries are trimmed and lowercased. Wildcards, htmLawed `+`/`-` operators, comma lists, custom (hyphenated) element names and non-strings are ignored. If nothing valid is left, every element is stripped.
- The attribute, URL and ID rules above still apply.

See [Extension hooks](../advanced/hooks.md) for the full hook reference.

## Restricting attributes with `$spec`

The third argument is an htmLawed [attribute specification](https://www.bioinformatics.org/phplabware/internal_utilities/htmLawed/htmLawed_README.htm#s2.3), as a string or a parsed array. Use it to deny or constrain attributes per element. Prefix an attribute with `-` to remove it:

```php
// Remove hreflang from links and width/height from images.
$clean = kses( $html, 1, 'a=-hreflang; img=-width, -height' );
// <a href="https://example.com" title="t">l</a><img src="https://example.com/a.png" alt="a" />
```

Under the default config, `$spec` can't re-enable `on*`, `style`, `class` or `ping` attributes: those entries are dropped before the spec reaches htmLawed. Directive attributes are still removed by `Security::ksesSafeTag()`.

## Custom configs

Passing any `$config` other than `1` hands full control to htmLawed: `$config` and `$spec` are forwarded unchanged, the `ksesAllowedTags` filter isn't consulted, and the safe-output guarantee no longer applies.

To change one safe rule while keeping the rest, start from `Security::KSES_SAFE_CONFIG`, keeping its `hook_tag`:

```php
use ArtisanPackUI\Security\Security;

// Allow class attributes (for example, for syntax-highlighted code blocks).
$config = Security::KSES_SAFE_CONFIG;
$config['deny_attribute'] = 'on*, ping, style';

$clean = kses( $html, $config );
```

When you do this, remember that the `$spec` protections described above no longer run, so a `$spec` passed alongside a custom config can permit any attribute.

## Upgrading from 2.1 or earlier

Before 2.2.0 the default `$config = 1` ran htmLawed with no filtering at all, so `<script>`, `on*` handlers and `javascript:` URLs passed through `kses()`. The new default removes far more, including `class` attributes, forms and non-HTTP URL schemes, and prefixes `id`/`name` values. If your content relied on any of that, pass your own `$config` (ideally built from `Security::KSES_SAFE_CONFIG`). See [UPGRADE.md](../../UPGRADE.md#upgrading-to-22).

## API

- `Security::kses( string $html, mixed $config = 1, mixed $spec = [] ): string`
- `kses( ?string $string = '', mixed $config = 1, mixed $spec = [] ): string`
- `Security::KSES_SAFE_CONFIG`: the default htmLawed config.
- `Security::KSES_ID_PREFIX`: the `id`/`name` prefix (`user-content-`).
- `Security::ksesSafeTag( string $element, array|int $attributes = 0 ): string`: the `hook_tag` callback used by `KSES_SAFE_CONFIG`.

See the [API reference](../api/reference.md#kses) for details.
