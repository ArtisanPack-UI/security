<?php

namespace ArtisanPackUI\Security;

use Illuminate\Support\ServiceProvider;

class SecurityServiceProvider extends ServiceProvider
{

	public function register(): void
	{
		$this->app->singleton( 'security', function ( $app ) {
			return new Security();
		} );
	}
}
