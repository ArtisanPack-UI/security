<?php
/**
 * Two-Factor Authentication Middleware
 *
 * Intercepts requests for authenticated users with 2FA enabled to ensure
 * they have completed the verification step.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\Http\Middleware
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Ensures a user has completed the two-factor authentication challenge.
 *
 * @since 1.2.0
 */
class TwoFactorMiddleware
{
	/**
	 * The session key for tracking 2FA verification status.
	 *
	 * This key is used to store a boolean value in the session to indicate
	 * that the user has successfully passed the two-factor challenge.
	 *
	 * @since 1.0.0
	 * @var string
	 */
	public const SESSION_KEY = 'two_factor_verified';

	/**
	 * Handle an incoming request.
	 *
	 * @since 1.2.0
	 *
	 * @param Request $request The incoming request.
	 * @param Closure $next    The next middleware in the chain.
	 * @return mixed
	 */
	public function handle( Request $request, Closure $next ): mixed
	{
		$user = $request->user();

		if (
			$user &&
			method_exists( $user, 'hasTwoFactorEnabled' ) &&
			$user->hasTwoFactorEnabled() &&
			! $request->session()->get( self::SESSION_KEY )
		) {
			return redirect()->route( config( 'artisanpack.security.routes.verify' ) );
		}

		return $next( $request );
	}
}