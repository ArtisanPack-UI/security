<?php
/**
 * Two-Factor Authenticatable Trait
 *
 * Provides the necessary properties and methods to enable two-factor
 * authentication on a user model.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\TwoFactor
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\TwoFactor;

use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use PragmaRX\Google2FA\Google2FA;
use RuntimeException;

/**
 * Provides two-factor authentication capabilities to a model.
 *
 * @since 1.2.0
 *
 * @property-read bool        $two_factor_enabled
 * @property      string|null $two_factor_secret
 * @property      string|null $two_factor_recovery_codes
 * @property      string|null $two_factor_enabled_at
 */
trait TwoFactorAuthenticatable
{
	/**
	 * Get the two_factor_enabled attribute.
	 *
	 * @since 1.2.0
	 *
	 * @return bool
	 */
	public function getTwoFactorEnabledAttribute(): bool
	{
		return $this->hasTwoFactorEnabled();
	}

	/**
	 * Determine if two-factor authentication is enabled.
	 *
	 * @since 1.2.0
	 *
	 * @return bool True if 2FA is enabled, false otherwise.
	 */
	public function hasTwoFactorEnabled(): bool
	{
		return ! is_null( $this->two_factor_enabled_at );
	}

	/**
	 * Generates a new secret key for authenticator-based 2FA.
	 *
	 * @since 1.2.0
	 *
	 * @return void
	 * @throws Exception If secret generation or saving fails.
	 */
	public function generateTwoFactorSecret(): void
	{
		try {
			$google2fa = app( Google2FA::class );

			$this->two_factor_secret = encrypt( $google2fa->generateSecretKey() );

			if ( ! $this->save() ) {
				throw new RuntimeException( 'Failed to save the new two-factor secret to the database.' );
			}
		} catch ( Exception $e ) {
			Log::error( 'Failed to generate 2FA secret for user: ' . $this->id, [
				'error' => $e->getMessage(),
			] );

			// Re-throw the exception so the calling code knows the operation failed.
			throw $e;
		}
	}

	/**
	 * Generates new recovery codes for the user.
	 *
	 * @since 1.2.0
	 *
	 * @return void
	 * @throws Exception If recovery code generation or saving fails.
	 */
	public function generateRecoveryCodes(): void
	{
		try {
			$this->two_factor_recovery_codes = encrypt(
				json_encode(
					Collection::times( 8, function () {
						return bin2hex( random_bytes( 8 ) );
					} )->all()
				)
			);

			if ( ! $this->save() ) {
				throw new RuntimeException( 'Failed to save new recovery codes to the database.' );
			}
		} catch ( Exception $e ) {
			Log::error( 'Failed to generate recovery codes for user: ' . $this->id, [
				'error' => $e->getMessage(),
			] );

			throw $e;
		}
	}
}