<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Orchestra\Testbench\TestCase as Orchestra;
use ArtisanPackUI\Security\SecurityServiceProvider;

class TestCase extends Orchestra
{
	protected function getPackageProviders( $app )
	{
		return [
			SecurityServiceProvider::class,
		];
	}

	protected function getEnvironmentSetUp($app): void
	{
		$app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
		$app['config']->set('database.default', 'testing');
		$app['config']->set('database.connections.testing', [
			'driver'   => 'sqlite',
			'database' => ':memory:',
			'prefix'   => '',
		]);

		// Create the users table that the package migrations depend on
		$app['db']->connection()->getSchemaBuilder()->create('users', function ($table) {
			$table->id();
			$table->string('name');
			$table->string('email')->unique();
			$table->timestamp('email_verified_at')->nullable();
			$table->string('password');
			$table->rememberToken();
			$table->timestamps();
		});
	}
}
