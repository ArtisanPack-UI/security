---
title: Extension Hooks
---

# Extension Hooks

The package fires a small set of [`artisanpack-ui/hooks`](https://github.com/ArtisanPack-UI/hooks) filters and actions so host applications can extend sanitization, escaping, KSES filtering, and CSP handling without subclassing. Register subscribers with `addFilter()` / `addAction()` (typically inside a service provider's `boot()` method).

> **Security note.** `ap.security.sanitizedInput` and `ap.security.escapedOutput` subscribers receive the *already sanitized/escaped* value and can return anything — including the untouched original — which effectively lets them weaken the guarantees this package provides. Only register callbacks you fully trust, and prefer narrowing (further sanitization) over broadening. The same applies to `ap.security.ksesAllowedTags`: a subscriber that returns a permissive tag list expands the attack surface of every `kses()` call in the app.

## Hook reference

| Hook | Type | When it fires | Payload |
|---|---|---|---|
| `ap.security.sanitizedInput` | filter | Wraps the return of every `Security::sanitize*` method (`email`, `url`, `filename`, `password`, `int`, `date`, `datetime`, `float`, `array`, `text`). `sanitizeArray` fires `text` per element before firing `array` on the whole result. | `(mixed $value, string $type, mixed $original)` |
| `ap.security.escapedOutput` | filter | Wraps the return of every `Security::esc*` method | `(string $value, string $context, string $original)` — `$context` is one of `html`, `attr`, `url`, `js`, `css` |
| `ap.security.ksesAllowedTags` | filter | At the start of `Security::kses()` **only when the caller uses the default `$config = 1`**; a non-empty return overrides htmLawed's element whitelist for that call. Explicit non-default `$config` bypasses this hook so caller intent isn't silently overridden. | `(array $allowedTags)` — lowercase element names, e.g. `['a', 'p', 'strong']` |
| `ap.security.csp.directives` | filter | Inside `CspPolicyService::getPolicy()` before the header is serialized; the mutated array is what gets serialized | `(array<string, array<string>\|bool> $directives, Illuminate\Http\Request $request)` |
| `ap.security.csp.violationHandled` | action | At the end of `CspViolationHandler::handle()` when a violation was stored (`csp.reporting.storeViolations = true`) | `(ArtisanPackUI\Security\Models\CspViolationReport $report)` |

## Examples

### Enforce a URL allowlist across every `escUrl()` call

```php
use function addFilter;

addFilter( 'ap.security.escapedOutput', function ( string $value, string $context, string $original ): string {
    if ( $context !== 'url' ) {
        return $value;
    }

    return app( UrlAllowlist::class )->passes( $original ) ? $value : '#blocked';
} );
```

### Ship stored CSP violations into your own alerting queue

```php
use ArtisanPackUI\Security\Models\CspViolationReport;
use function addAction;

addAction( 'ap.security.csp.violationHandled', function ( CspViolationReport $report ): void {
    SecurityAlerts::dispatch( $report );
} );
```

### Tighten the default KSES allow-list

```php
use function addFilter;

addFilter( 'ap.security.ksesAllowedTags', function ( array $allowedTags ): array {
    return array_values( array_diff( $allowedTags, [ 'iframe', 'object', 'embed' ] ) );
} );
```

### Inject a per-request CSP source

```php
use Illuminate\Http\Request;
use function addFilter;

addFilter( 'ap.security.csp.directives', function ( array $directives, Request $request ): array {
    if ( $request->is( 'checkout/*' ) ) {
        $directives['connect-src'][] = 'https://api.stripe.com';
    }

    return $directives;
} );
```

## Registration guidance

- Register subscribers in a service provider's `boot()` method so they are wired before the first HTTP request.
- Use descriptive callback closures or dedicated invokable classes — the hook name is the only registration key, so anonymous callbacks are hard to remove or debug later.
- Keep callbacks fast: filters run on every sanitize / escape / CSP call in the request lifecycle.
