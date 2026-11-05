# Upgrade Guide

## Upgrading to 2.2

2.2 has no API removals, but `kses()` now filters HTML by default. Before 2.2 the default `$config = 1` ran htmLawed with no filtering, so `<script>`, `on*` handlers and `javascript:` URLs survived. That default now applies `Security::KSES_SAFE_CONFIG`, which affects `kses()`, `Security::kses()`, the `html` sanitization rule (`Security::sanitize()`, `BaseFormRequest`) and the `XssProtection` middleware.

Content run through the default config now loses:

- `<script>`, `<iframe>`, `<object>`, `<embed>` and other executable elements;
- `<style>`, `<link>`, `<meta>`, `<base>`, `<form>` and form controls, and `<frame>`/`<frameset>`;
- custom (hyphenated) elements, such as `<x-alert>`;
- `on*`, `style`, `class` and `ping` attributes, plus Alpine/Livewire directives (`x-*`, `@*`, `:*`, `wire:*`) and `is`;
- URL schemes other than `http`/`https` (and `mailto`/`tel` for `href`), which are rewritten to `denied:…`.

It also gains a `user-content-` prefix on `id`/`name` values (with matching `#fragment` links and ID references), and `rel="noopener"` on links with a `target`.

**What to check:**

1. Search for `kses(` calls and `'html'` sanitization rules whose output relies on any of the markup above, such as CSS classes from a rich-text editor, embedded forms, or in-page anchors targeted by your own CSS or JavaScript.
2. For those, pass your own `$config`. To keep the other safe rules, start from `Security::KSES_SAFE_CONFIG` and change one key:

   ```php
   use ArtisanPackUI\Security\Security;

   $config = Security::KSES_SAFE_CONFIG;
   $config['deny_attribute'] = 'on*, ping, style'; // allow class

   $html = kses( $html, $config );
   ```

3. If you passed `$config` or `$spec` to the global `kses()` helper, they were silently dropped before 2.2. The helper now forwards them like `Security::kses()` does, so check those calls still give the output you expect.
4. `ap.security.ksesAllowedTags` subscribers can no longer re-enable unsafe elements (`script`, `style`, `iframe`, forms, frames, …) or custom elements, and wildcard or htmLawed `+`/`-` entries are ignored. Return a plain list of element names.

Any `$config` other than `1` keeps its 2.1 behavior. See [HTML filtering](docs/usage/html-filtering.md) for the full rule set.

## Upgrading from artisanpack-ui/security 1.x to 2.0

Security 2.0 is a **major repackaging**. The monolithic 1.x package has been split into a small core (this package) plus six sibling packages. Functionality is preserved — most of the migration is dependency installation + namespace tweaks.

### TL;DR

1. Bump `artisanpack-ui/security` to `^2.0`.
2. Add the sibling packages you actually use (table below).
3. Update namespaces (`ArtisanPackUI\Security\…` → sibling namespace) for moved classes.
4. Update config paths — sibling packages publish their own config files.
5. Re-run `php artisan migrate`. Sibling migrations are guarded by `Schema::hasTable()` so they're safe to re-run.

### What stays in `artisanpack-ui/security`

The core security toolkit:

- Sanitization helpers + facade methods
- Escaping helpers (Laminas Escaper)
- KSES HTML filtering
- `NoHtml` and `SecureUrl` validation rules
- Middleware: `csp`, `security.headers`, `xss.protection`, `api.security`, `api.rate_limit`
- Content Security Policy (nonce generator, policy service, presets, violation report endpoint, dashboard, commands)
- Security audit + scan + baseline + benchmark Artisan commands
- Testing infrastructure (OWASP/configuration scanners, penetration testing helpers, report generators)

If your application only used these features, no namespace changes are required.

### What moved out

| 1.x feature | New package | New namespace prefix |
|---|---|---|
| Email + TOTP 2FA, password complexity, HIBP breach check, account lockout, advanced session manager | `artisanpack-ui/security-auth` | `ArtisanPackUI\SecurityAuth\` |
| WebAuthn / FIDO2, SAML / OIDC SSO, social auth, biometric, device fingerprinting | `artisanpack-ui/security-advanced-auth` | `ArtisanPackUI\SecurityAdvancedAuth\` |
| Roles, permissions, `HasRoles` trait, `@role` / `@permission` Blade directives | `artisanpack-ui/rbac` | `ArtisanPackUI\Rbac\` |
| Secure file uploads, validation, malware scanning, `HasSecureFiles` trait, `SecureFile` rule, `PasswordPolicy` rule | `artisanpack-ui/secure-uploads` (uploads) / `artisanpack-ui/security-auth` (`PasswordPolicy`) | `ArtisanPackUI\SecureUploads\` / `ArtisanPackUI\SecurityAuth\` |
| Security event logging, anomaly detection, threat intel, SIEM export, incident response, alerting, dashboards | `artisanpack-ui/security-analytics` | `ArtisanPackUI\SecurityAnalytics\` |
| GDPR / CCPA / LGPD — consent, DSR (erasure / portability), DPIA, retention, `PrivacyByDesign` + `Auditable` traits | `artisanpack-ui/compliance` | `ArtisanPackUI\Compliance\` |

### Step-by-step

#### 1. Update `composer.json`

```diff
 "require": {
-    "artisanpack-ui/security": "^1.0"
+    "artisanpack-ui/security": "^2.0",
+    "artisanpack-ui/security-auth": "^1.0",
+    "artisanpack-ui/rbac": "^1.0",
+    "artisanpack-ui/secure-uploads": "^1.0",
+    "artisanpack-ui/security-analytics": "^1.0",
+    "artisanpack-ui/compliance": "^1.0"
 }
```

Only require the siblings you actually use.

#### 2. Update namespaces

Search-and-replace per the table above. Examples:

```diff
-use ArtisanPackUI\Security\Concerns\HasRoles;
+use ArtisanPackUI\Rbac\Concerns\HasRoles;

-use ArtisanPackUI\Security\Rules\PasswordPolicy;
+use ArtisanPackUI\SecurityAuth\Rules\PasswordPolicy;

-use ArtisanPackUI\Security\Rules\SecureFile;
+use ArtisanPackUI\SecureUploads\Rules\SecureFile;

-use ArtisanPackUI\Security\TwoFactor\TwoFactorAuthenticatable;
+use ArtisanPackUI\SecurityAuth\TwoFactor\TwoFactorAuthenticatable;

-use ArtisanPackUI\Security\Concerns\PrivacyByDesign;
+use ArtisanPackUI\Compliance\Traits\PrivacyByDesign;
```

#### 3. Update config references

Each sibling package publishes its own config. The 1.x config keys stayed under `artisanpack.security.*`; sibling configs now live under their own namespace. For example:

```diff
-config('artisanpack.security.compliance.consent.…')
+config('artisanpack.compliance.consent.…')

-config('artisanpack.security.analytics.…')
+config('artisanpack.security_analytics.…')
```

Re-run `php artisan vendor:publish --tag=…-config` for each sibling you install.

#### 4. Migrations

Sibling migrations are **idempotent** — they all wrap `Schema::create()` in `Schema::hasTable()` checks, so running them against a database that was previously migrated by `artisanpack-ui/security` 1.x will simply skip existing tables. Run:

```bash
php artisan migrate
```

#### 5. Removed config sections

The `artisanpack.security` config has been slimmed to core only. The following sections moved into sibling configs:

- `auth.*`, `password.*`, `2fa.*` → `artisanpack.security_auth`
- `roles.*`, `permissions.*` → `artisanpack.rbac`
- `fileUpload.*`, `scanners.*` → `artisanpack.secure_uploads`
- `events.*`, `analytics.*`, `siem.*`, `threatIntel.*` → `artisanpack.security_analytics`
- `compliance.*` → `artisanpack.compliance`

#### 6. Service provider auto-discovery

Sibling providers register themselves via Laravel's package discovery — no manual registration required.

### Common gotchas

- **`HasRoles` / `@role` / `@permission` no longer ship with `artisanpack-ui/security`.** Add `artisanpack-ui/rbac`.
- **`TwoFactor` facade no longer ships with `artisanpack-ui/security`.** Add `artisanpack-ui/security-auth`.
- **`SecureFile` validation rule moved.** Add `artisanpack-ui/secure-uploads`.
- **API token management** (`HasApiTokens` concern, token CRUD endpoints) moved to `artisanpack-ui/security-auth`. The `api.security` and `api.rate_limit` middleware remain core.

### Help

- [Changelog](CHANGELOG.md)
- File issues at the package's repository.
