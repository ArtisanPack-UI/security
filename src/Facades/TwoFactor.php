<?php
/**
 * TwoFactor Facade
 *
 * Provides a static interface to the TwoFactorManager service.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\Facades
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\Facades;

use ArtisanPackUI\Security\TwoFactor\TwoFactorManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Facade;

/**
 * Provides a static accessor to the TwoFactorManager.
 *
 * @since 1.2.0
 *
 * @method static void generateChallenge( Authenticatable $user )
 * @method static bool verify( Authenticatable $user, string $code )
 * @see   TwoFactorManager
 */
class TwoFactor extends Facade
{
	/**
	 * Get the registered name of the component.
	 *
	 * @since 1.2.0
	 *
	 * @return string
	 */
	protected static function getFacadeAccessor(): string
	{
		return TwoFactorManager::class;
	}
}