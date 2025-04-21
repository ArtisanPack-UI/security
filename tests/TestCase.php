<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Orchestra\Testbench\TestCase as Orchestra;
use Digitalshopfront\Security\SecurityServiceProvider;

class TestCase extends Orchestra
{
    protected function getPackageProviders( $app )
    {
        return [
            SecurityServiceProvider::class,
        ];
    }
}
