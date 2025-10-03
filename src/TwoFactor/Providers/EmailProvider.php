<?php
/**
 * Email-based Two-Factor Provider
 *
 * Handles two-factor authentication by generating a code, storing it in the
 * session, and emailing it to the user.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\TwoFactor\Providers
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\TwoFactor\Providers;

use ArtisanPackUI\Security\Mail\TwoFactorCodeMailable;
use ArtisanPackUI\Security\TwoFactor\Contracts\TwoFactorProvider;
use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Mail;
use InvalidArgumentException;
use RuntimeException;
use Illuminate\Support\Facades\RateLimiter;

/**
 * Implements email-based two-factor authentication.
 *
 * @since 1.2.0
 */
class EmailProvider implements TwoFactorProvider
{
	/**
	 * Generate and send a two-factor challenge to the user.
	 *
	 * @since 1.2.0
	 *
	 * @param Authenticatable $user The user to send the challenge to.
	 * @return void
	 *
	 * @throws Exception If rate limit is exceeded.
	 * @throws InvalidArgumentException If the user does not have a valid email address.
	 * @throws RuntimeException If the email fails to send.
	 */
	public function generateChallenge( Authenticatable $user ): void
	{
		// 1. Rate Limiting
		$key = 'two-factor-challenge:' . $user->getAuthIdentifier();
		if ( RateLimiter::tooManyAttempts( $key, 3 ) ) {
			throw new Exception( 'Too many code generation attempts. Please try again later.' );
		}

		// 2. Validate Email
		if ( ! isset( $user->email ) || ! filter_var( $user->email, FILTER_VALIDATE_EMAIL ) ) {
			throw new InvalidArgumentException( 'User must have a valid email address for 2FA.' );
		}

		RateLimiter::hit( $key, 900 ); // Lock for 15 minutes (900 seconds)

		$code = random_int( 100000, 999999 );

		// 3. Handle Mail Failures
		try {
			Mail::to( $user->email )->send( new TwoFactorCodeMailable( $code ) );
		} catch ( Exception $e ) {
			// If mail fails, clear the rate limiter so the user can try again.
			RateLimiter::clear( $key );
			throw new RuntimeException( 'Failed to send 2FA code. Please try again.', 0, $e );
		}

		// ONLY set the session after the email has been sent successfully.
		session( [
					 'two_factor_code'    => $code,
					 'two_factor_expires' => now()->addMinutes( 10 ),
					 'two_factor_user_id' => $user->getAuthIdentifier(),
				 ] );
	}

	/**
	 * Verifies the provided two-factor authentication code.
	 *
	 * Includes rate limiting to protect against brute-force attacks.
	 *
	 * @since 1.2.0
	 *
	 * @param Authenticatable $user The user attempting to verify.
	 * @param string          $code The 2FA code to verify.
	 * @return bool True if the code is valid, false otherwise.
	 */
	public function verify( Authenticatable $user, string $code ): bool
	{
		$key = 'two-factor-verify:' . $user->getAuthIdentifier();

		// 1. If rate limit is exceeded, invalidate the session and block the attempt.
		if ( RateLimiter::tooManyAttempts( $key, 5 ) ) {
			session()->forget( [ 'two_factor_code', 'two_factor_expires', 'two_factor_user_id' ] );
			return false;
		}

		// Pull all session data first to mitigate timing attacks.
		$storedUserId = session( 'two_factor_user_id' );
		$storedCode   = (string) session( 'two_factor_code' );
		$expiry       = session( 'two_factor_expires' );

		// 2. Validate all conditions.
		if (
			$storedUserId !== $user->getAuthIdentifier() ||
			! $expiry || now()->isAfter( $expiry ) ||
			! hash_equals( $storedCode, $code )
		) {
			// If any check fails, log the failed attempt.
			RateLimiter::hit( $key, 900 ); // Lock for 15 minutes
			return false;
		}

		// 3. On success, clear the session data and the rate limiter.
		session()->forget( [ 'two_factor_code', 'two_factor_expires', 'two_factor_user_id' ] );
		RateLimiter::clear( $key );

		return true;
	}
}