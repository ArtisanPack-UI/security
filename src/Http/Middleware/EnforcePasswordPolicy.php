<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Contracts\PasswordSecurityServiceInterface;
use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnforcePasswordPolicy
{
    /**
     * The password security service.
     */
    protected PasswordSecurityServiceInterface $passwordService;

    /**
     * The security event logger.
     */
    protected ?SecurityEventLoggerInterface $logger;

    /**
     * Create a new middleware instance.
     */
    public function __construct(
        PasswordSecurityServiceInterface $passwordService,
        ?SecurityEventLoggerInterface $logger = null
    ) {
        $this->passwordService = $passwordService;
        $this->logger = $logger;
    }

    /**
     * Handle password validation on registration/password change routes.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('artisanpack.security.passwordSecurity.enabled', true)) {
            return $next($request);
        }

        // Only validate on POST/PUT/PATCH requests with password field
        if (! in_array($request->method(), ['POST', 'PUT', 'PATCH'], true)) {
            return $next($request);
        }

        $password = $request->input('password');

        if ($password === null) {
            return $next($request);
        }

        $user = $request->user();
        $errors = $this->passwordService->validatePassword($password, $user);

        if (! empty($errors)) {
            $this->logValidationFailure($request, $errors);

            if ($request->expectsJson()) {
                return response()->json([
                    'message' => 'Password does not meet security requirements.',
                    'errors' => ['password' => $errors],
                ], 422);
            }

            return back()
                ->withInput($request->except('password', 'password_confirmation'))
                ->withErrors(['password' => $errors]);
        }

        return $next($request);
    }

    /**
     * Log a validation failure event.
     */
    protected function logValidationFailure(Request $request, array $errors): void
    {
        if (! config('artisanpack.security.passwordSecurity.logging.failedValidations', true)) {
            return;
        }

        $this->logger?->authentication('password_validation_failed', [
            'user_id' => $request->user()?->id,
            'route' => $request->route()?->getName(),
            'errors' => $errors,
        ]);
    }
}
