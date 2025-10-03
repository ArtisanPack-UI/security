<?php
/**
 * Two-Factor Provider Interface
 *
 * Defines the contract for all two-factor authentication providers, ensuring
 * they implement a consistent API for generating challenges and verifying codes.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\TwoFactor\Contracts
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\TwoFactor\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Interface for a two-factor authentication provider.
 *
 * @since 1.2.0
 */
interface TwoFactorProvider
{
	/**
	 * Generate and dispatch a two-factor authentication challenge to the user.
	 *
	 * For email, this sends the code. For an authenticator app, this method
	 * might not need to do anything as the challenge is ongoing.
	 *
	 * @since 1.2.0
	 *
	 * @param Authenticatable $user The user to send the challenge to.
	 * @return void
	 */
	public function generateChallenge( Authenticatable $user ): void;

	/**
	 * Verify a given two-factor authentication code.
	 *
	 * @since 1.2.0
	 *
	 * @param Authenticatable $user The user attempting to verify.
	 * @param string          $code The code provided by the user.
	 * @return bool True if the code is valid, false otherwise.
	 */
	public function verify( Authenticatable $user, string $code ): bool;
}