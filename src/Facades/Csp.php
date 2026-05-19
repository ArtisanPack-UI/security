<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Facades;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use Illuminate\Support\Facades\Facade;

/**
 * @method static string getNonce()
 * @method static self addDirective(string $directive, string|array $values)
 * @method static string getPolicy()
 * @method static string getReportOnlyPolicy()
 * @method static array toHeader()
 * @method static self forRequest(\Illuminate\Http\Request $request)
 * @method static self usePreset(string $preset)
 * @method static string renderMetaTag()
 * @method static self reset()
 *
 * @see \ArtisanPackUI\Security\Services\Csp\CspPolicyService
 */
class Csp extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return CspPolicyInterface::class;
    }
}
