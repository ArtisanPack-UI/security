<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \ArtisanPackUI\Security\Security
 */
class Security extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'security';
    }
}
