<?php

namespace Digitalshopfront\Security\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Digitalshopfront\Security\Security
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
