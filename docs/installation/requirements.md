---
title: Requirements
---

# Requirements

## PHP

- PHP 8.2 or higher

## Laravel

- Laravel 10 / 11 / 12

## Runtime dependencies

Pulled in automatically by Composer:

- `artisanpack-ui/core: ^1.0`
- `laminas/laminas-escaper: ^2.16` — backs the escape helpers
- `laravel/sanctum: ^4.0` — required for the `api.security` middleware's token validation flow

## Optional

- `livewire/livewire: ^3.6|^4.0` — only required if you want to use the CSP dashboard Livewire component. The service provider skip-registers the component when Livewire isn't installed; the rest of the package works regardless.

## Database

Any Eloquent-supported driver. The shipped migration uses standard column types — no driver-specific syntax.

The single shipped migration creates the `csp_violation_reports` table used by the CSP violation reporting endpoint. Disable the route + skip the migration via config if you don't want to receive violation reports.

## Cache

Any Laravel cache driver. The package's rate limiter and CSP nonce generator use the application's default cache store — no first-class cache config required.
