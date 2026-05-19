<?php

/**
 * CspViolationController controller.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Controllers;

use ArtisanPackUI\Security\Services\Csp\CspViolationHandler;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;

class CspViolationController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected CspViolationHandler $handler,
    ) {}

    /**
     * Handle a CSP violation report.
     */
    public function report(Request $request): Response
    {
        // CSP reports come as JSON
        $report = $request->json()->all();

        // Process the violation
        $this->handler->handle($report);

        // Return 204 No Content (standard response for CSP reports)
        return response()->noContent();
    }
}
