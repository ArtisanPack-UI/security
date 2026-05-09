<?php

declare(strict_types=1);

use ArtisanPackUI\Security\Http\Controllers\CspViolationController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| CSP Routes
|--------------------------------------------------------------------------
|
| These routes handle Content Security Policy violation reporting.
|
*/

if (config('artisanpack.security.csp.reporting.enabled', true)) {
    Route::post(
        config('artisanpack.security.csp.reporting.uri', '/csp-violation'),
        [CspViolationController::class, 'report'],
    )->name('csp.violation.report');
}
