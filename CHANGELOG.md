# ArtisanPack UI Security Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `kses()` now filters executable markup with its default config. Previously the default `$config = 1` ran htmLawed with no filtering, so `<script>`, `on*` event handlers and `javascript:` URLs survived and `{!! kses( $html ) !!}` was open to stored XSS. The default is now `Security::KSES_SAFE_CONFIG` (htmLawed safe mode, no `<style>`, `<link>` or `<meta>` elements, no `on*` or `style` attributes); `javascript:` and `data:` URLs are rewritten to `denied:…`. **Behavior change:** callers that relied on the permissive default must now pass their own `$config`. `sanitize()` / `BaseFormRequest` with the `html` rule and the opt-in `XssProtection` middleware pick up the same default. Passing any config other than `1` is forwarded unchanged ([#52](https://github.com/ArtisanPack-UI/security/issues/52), [#53](https://github.com/ArtisanPack-UI/security/issues/53)).
- The default `kses()` config also removes elements that can restyle or hijack the page: `<base>`, `<form>` and form controls (`<input>`, `<button>`, `<select>`, `<option>`, `<optgroup>`, `<textarea>`, `<datalist>`, `<keygen>`, `<isindex>`) and frames (`<frame>`, `<frameset>`), which allowed fake login forms on the site's own origin. URLs are limited to `http`/`https`, plus `mailto` and `tel` for `href`; any other scheme (`ftp:`, `file:`, …) is rewritten to `denied:…`. Relative and fragment URLs are kept. Custom (hyphenated) elements are now dropped (their text is kept) and the `ping` attribute is denied: htmLawed let custom elements keep every attribute, so Alpine/Livewire directives such as `<x-a x-data x-init="…">` survived `kses()` and ran as script. Custom element names returned by `ap.security.ksesAllowedTags` are ignored for the same reason. The default also removes `class` attributes (so content can't borrow the site's CSS classes for a full-page phishing overlay) and Alpine/Livewire directive attributes (`x-*`, `@*`, `:*`, `wire:*`) and `is` on every element, even when `$spec` permits them. It drops `rel="opener"` and adds `noopener` to links with a `target` (reverse tabnabbing), and prefixes `id`/`name` values with `user-content-` (DOM clobbering). `#fragment` links and ID references (`usemap`, `headers`, `for`, `aria-labelledby`, …) are rewritten to match, and sanitizing already-prefixed output again leaves it unchanged. New public `Security::KSES_ID_PREFIX` and `Security::ksesSafeTag()` (the `hook_tag` in `KSES_SAFE_CONFIG`). **Behavior change:** content that relied on forms or other URL schemes passing through `kses()` must pass its own `$config` ([#50](https://github.com/ArtisanPack-UI/security/issues/50)).
- Under the default config, `$spec` can no longer re-enable `on*`, `style`, `class` or `ping` attributes (htmLawed lets `$spec` override `deny_attribute`). Those entries are dropped before the spec reaches htmLawed ([#52](https://github.com/ArtisanPack-UI/security/issues/52)).
- Tags returned by the `ap.security.ksesAllowedTags` filter can no longer re-enable `script`, `style`, `link`, `meta`, `base`, `iframe`, `frame`, `frameset`, `object`, `embed`, `applet`, `audio`, `video`, `canvas`, `dialog`, or forms and form controls. Entries are trimmed and lowercased, and anything that isn't a plain element name (wildcards, htmLawed `+`/`-` operators, comma lists, non-strings) is ignored. The safe attribute and URL rules also apply to the filtered list ([#50](https://github.com/ArtisanPack-UI/security/issues/50), [#52](https://github.com/ArtisanPack-UI/security/issues/52)).

### Added

- The release workflow now has a `sync-docs` job that queues documentation and changelog imports on docs.artisanpackui.dev after each release. It needs the `DOCS_API_TOKEN` org secret and skips with a notice when the secret isn't set. Both imports are attempted on every run, and the job fails unless each returns `202`. Set a `DOCS_PACKAGE_SLUG` repository variable if the docs-site slug ever differs from the repo name. The Packagist update now runs in its own job, so a Packagist failure no longer blocks the docs import, and the workflow defaults to read-only `GITHUB_TOKEN` permissions ([#51](https://github.com/ArtisanPack-UI/security/issues/51)).

### Changed

- The global `kses()` helper now accepts and forwards `$config` and `$spec` like `Security::kses()`. Previously it silently dropped them ([#52](https://github.com/ArtisanPack-UI/security/issues/52)).

### Fixed

- Bundled htmLawed: safe mode no longer throws on `style` attributes containing `url(…)` (the `hl_url` callback didn't resolve in the namespaced copy). Corrupted `srcset`/`archive`/`itemtype` and `abs_url` code paths are repaired, and `$spec` strings now parse on every call instead of failing on the namespaced `hl_aux1`/`hl_aux2` callbacks. `srcset` values are no longer run through `hl_url()` a second time (which double-converted the first candidate under `abs_url`). A `$spec` `default` for a URL attribute now gets the same scheme check as the original value. A `style` attribute generated from deprecated markup (`<center>`, `<font>`, `align`, `bgcolor`, …) is dropped when `deny_attribute` denies `style` ([#52](https://github.com/ArtisanPack-UI/security/issues/52), [#53](https://github.com/ArtisanPack-UI/security/issues/53)).

## [2.1.0] - 2026-07-21

### Added

- Extension hooks powered by `artisanpack-ui/hooks` (^1.2):
  - `ap.security.sanitizedInput` filter — wraps every `Security::sanitize*` return with `(mixed $value, string $type, mixed $original)`.
  - `ap.security.escapedOutput` filter — wraps every `Security::esc*` return with `(string $value, string $context, string $original)`.
  - `ap.security.ksesAllowedTags` filter — receives `(array $allowedTags)` from `Security::kses()`; a non-empty return overrides htmLawed's element whitelist for the call.
  - `ap.security.csp.directives` filter — fires inside `CspPolicyService::getPolicy()` with `(array $directives, Request $request)`, letting host apps mutate the directive array before it is serialized.
  - `ap.security.csp.violationHandled` action — fires at the end of `CspViolationHandler::handle()` on stored violations with `(CspViolationReport $report)`.
  - See the README "Hooks" section for full payload details and examples.

### Fixed

- `Security::sanitizeFloat()` was declared to return `float` but returned the raw `number_format()` string, which raised a `TypeError` under `strict_types=1` any time the method was actually called. The result is now explicitly cast to `float` before return.

## [2.0.2] - 2026-06-09

### Added

- Laravel 13 support. Widened the `illuminate/support` constraint to `^10.0|^11.0|^12.0|^13.0`. Existing Laravel 10/11/12 users are unaffected; Laravel 13 is only selectable on PHP 8.3+ per its own framework constraint.

### Changed

- Widened `orchestra/testbench` dev requirement to `^10.2|^11.0` so package tests can install against Laravel 13.
- Swept the package through Laravel Pint to bring it back in line with the configured code style (no behavioral changes).

## [2.0.1] - 2026-05-21

### Fixed

- Restore the `csp:test` command (`CspTest`) to the distributed package. An over-broad `export-ignore` rule (`/src/**/*Test.php`) stripped it from the release tarball, so `SecurityServiceProvider` registered a class that wasn't shipped — causing `Target class [ArtisanPackUI\Security\Console\Commands\CspTest] does not exist` during package discovery for every consumer.

## [2.0.0] - 2026-05-18

### Changed

- Promotes the `2.0.0-alpha.1` feature surface to the stable `2.0.0` release. No code changes from the alpha — see the alpha entry below for the complete 2.0 changelog.

## [2.0.0-alpha.1] - 2026-05-09

### Changed

- **BREAKING**: Repackaged from monolithic security toolkit into a focused core package plus sibling packages. Authentication, 2FA, RBAC, secure uploads, security analytics, and compliance now live in their own packages. See [UPGRADE.md](UPGRADE.md) for the full migration guide.

### Added

- Content Security Policy subsystem: nonce generator, policy service, policy builder, three presets (`Strict`, `Relaxed`, `Livewire`), violation reporting endpoint, `csp-dashboard` Livewire component, and Artisan commands (`csp:test`, `csp:stats`, `csp:prune`, `csp:generate`).
- Security testing toolkit: OWASP / header / dependency / configuration scanners, penetration attack simulator (SQL, XSS, CSRF, path traversal, auth bypass, injection), report generators (JSON, HTML, JUnit, SARIF, Markdown), benchmark suite, security gate, and GitHub Actions integration.
- Security audit Artisan commands: `security:audit`, `security:scan`, `security:baseline`, `security:benchmark`, `security:check-config`, `security:test-headers`, `security:scan-deps`, `security:clear-rate-limits`.
- `Csp` Facade alongside the existing `Security` Facade.
- `@csp_nonce` Blade directive and `<x-csp-nonce>` component.
- Named rate limiters driven from config (`web`, `api`, `login`, `password_reset`).

### Removed

- Authentication, 2FA, password complexity, account lockout, advanced sessions → moved to `artisanpack-ui/security-auth`.
- WebAuthn / FIDO2, SSO, social auth, biometric, device fingerprinting → moved to `artisanpack-ui/security-advanced-auth`.
- Roles, permissions, Blade directives, Gate integration → moved to `artisanpack-ui/rbac`.
- Secure file uploads, validation, malware scanning → moved to `artisanpack-ui/secure-uploads`.
- Security event logging, anomaly detection, SIEM export, incident response → moved to `artisanpack-ui/security-analytics`.
- GDPR / CCPA / LGPD compliance toolkit → moved to `artisanpack-ui/compliance`.

## [1.0.3] - 2025-05-14

### Changed

- Renamed vendor to ArtisanPack UI.

## [1.0.2] - 2025-04-21

### Fixed

- Issue with the `kses()` function.

### Added

- Tests and a GitLab pipeline.

## [1.0.1] - 2025-04-20

### Removed

- Unnecessary files from the published package.

## [1.0.0] - 2025-04-17

### Added

- Initial release.
