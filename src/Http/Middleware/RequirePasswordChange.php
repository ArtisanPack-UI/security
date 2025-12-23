<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequirePasswordChange
{
    /**
     * Routes that should be accessible even when password change is required.
     *
     * @var array<int, string>
     */
    protected array $exceptRoutes = [
        'password.change',
        'password.update',
        'logout',
    ];

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('artisanpack.security.passwordSecurity.expiration.enabled', false)) {
            return $next($request);
        }

        $user = $request->user();

        if (! $user) {
            return $next($request);
        }

        // Check if current route is exempt
        $currentRoute = $request->route()?->getName();
        if ($currentRoute && in_array($currentRoute, $this->exceptRoutes, true)) {
            return $next($request);
        }

        // Check for forced password change
        if ($user->force_password_change ?? false) {
            return $this->redirectToPasswordChange($request, 'Your password must be changed.');
        }

        // Check if method exists (trait may not be applied)
        if (! method_exists($user, 'passwordHasExpired')) {
            return $next($request);
        }

        // Check password expiration
        if ($user->passwordHasExpired()) {
            // Check grace logins
            if ($user->hasGraceLoginsRemaining()) {
                // Calculate remaining logins after this one (before decrementing)
                $remainingAfterThis = $user->grace_logins_remaining - 1;

                $user->decrementGraceLogins();

                session()->flash('password_warning', sprintf(
                    'Your password has expired. You have %d login(s) remaining before you must change it.',
                    $remainingAfterThis
                ));

                return $next($request);
            }

            return $this->redirectToPasswordChange($request, 'Your password has expired and must be changed.');
        }

        // Check if password is expiring soon (warning only)
        if ($user->passwordExpiringSoon()) {
            $days = $user->daysUntilPasswordExpires();
            session()->flash('password_warning', sprintf(
                'Your password will expire in %d day(s). Please change it soon.',
                $days
            ));
        }

        return $next($request);
    }

    /**
     * Redirect the user to the password change page.
     */
    protected function redirectToPasswordChange(Request $request, string $message): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'message' => $message,
                'password_change_required' => true,
            ], 403);
        }

        return redirect()
            ->route('password.change')
            ->with('password_error', $message);
    }
}
