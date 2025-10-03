<?php
/**
 * Two-Factor Authentication Manager
 *
 * Acts as a factory for resolving and managing two-factor authentication providers.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\TwoFactor
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\TwoFactor;

use ArtisanPackUI\Security\TwoFactor\Contracts\TwoFactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\App;
use InvalidArgumentException;

/**
 * Manages two-factor authentication provider resolution.
 *
 * @since 1.2.0
 *
 * @method void generateChallenge( Authenticatable $user )
 * @method bool verify( Authenticatable $user, string $code )
 */
class TwoFactorManager
{
	/**
	 * The array of resolved two-factor providers.
	 *
	 * @since 1.2.0
	 * @var array
	 */
	protected array $providers = [];

	/**
	 * Dynamically call the default driver instance.
	 *
	 * @since 1.2.0
	 *
	 * @param string $method     The method to call.
	 * @param array  $parameters The parameters to pass to the method.
	 * @return mixed
	 */
	public function __call( string $method, array $parameters )
	{
		return $this->provider()->{$method}( ...$parameters );
	}

	/**
	 * Get a two-factor provider instance.
	 *
	 * @since 1.2.0
	 *
	 * @param string|null $name The name of the provider to resolve.
	 * @return TwoFactorProvider
	 */
	public function provider( ?string $name = null ): TwoFactorProvider
	{
		$name = $name ?: $this->getDefaultDriver();

		if ( ! isset( $this->providers[ $name ] ) ) {
			$this->providers[ $name ] = $this->resolve( $name );
		}

		return $this->providers[ $name ];
	}

	/**
	 * Get the default two-factor driver name.
	 *
	 * @since 1.2.0
	 *
	 * @return string
	 * @throws InvalidArgumentException If a default driver is not configured.
	 */
	public function getDefaultDriver(): string
	{
		$default = config( 'artisanpack.security.two_factor.default' );

		if ( is_null( $default ) ) {
			throw new InvalidArgumentException( 'No default two-factor provider has been configured.' );
		}

		return $default;
	}

	/**
	 * Resolve a given provider.
	 *
	 * @since 1.2.0
	 *
	 * @param string $name The name of the provider.
	 * @return \ArtisanPackUI\Security\Contracts\TwoFactorProvider
	 *
	 * @throws InvalidArgumentException If the provider is not defined, does not specify a driver, or the driver is
	 *                                   invalid.
	 */
	protected function resolve( string $name ): TwoFactorProvider
	{
		$config = config( "security.two_factor.providers.{$name}" );

		if ( is_null( $config ) ) {
			throw new InvalidArgumentException( "Two-factor provider [{$name}] is not defined." );
		}

		if ( ! isset( $config['driver'] ) ) {
			throw new InvalidArgumentException( "Two-factor provider [{$name}] does not specify a driver." );
		}

		$instance = App::make( $config['driver'] );

		if ( ! $instance instanceof TwoFactorProvider ) {
			throw new InvalidArgumentException(
				"Driver [{$config['driver']}] for two-factor provider [{$name}] must implement the TwoFactorProvider interface."
			);
		}

		return $instance;
	}
}