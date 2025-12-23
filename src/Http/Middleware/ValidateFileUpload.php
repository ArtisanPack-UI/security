<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Contracts\FileValidatorInterface;
use ArtisanPackUI\Security\Events\FileUploadRejected;
use ArtisanPackUI\Security\FileUpload\RequestContext;
use ArtisanPackUI\Security\Services\FileUploadRateLimiter;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Symfony\Component\HttpFoundation\Response;

class ValidateFileUpload
{
    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected FileValidatorInterface $validator,
        protected FileUploadRateLimiter $rateLimiter,
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     * @param  string  ...$allowedTypes  Optional MIME type patterns to allow
     */
    public function handle(Request $request, Closure $next, ...$allowedTypes): Response
    {
        // Skip if file upload security is disabled
        if (! config('artisanpack.security.fileUpload.enabled', true)) {
            return $next($request);
        }

        // Check rate limiting
        if (config('artisanpack.security.fileUpload.rateLimiting.enabled', true)) {
            $totalSize = $this->calculateTotalUploadSize($request);

            if (! $this->rateLimiter->attempt($request, $totalSize)) {
                return $this->rateLimitResponse($request);
            }
        }

        // Get all uploaded files from the request
        $files = $this->getAllUploadedFiles($request);

        if (empty($files)) {
            return $next($request);
        }

        // Validate each file
        $errors = [];

        foreach ($files as $key => $file) {
            if ($file instanceof UploadedFile) {
                $result = $this->validator->validate($file, [
                    'allowedMimeTypes' => ! empty($allowedTypes) ? $allowedTypes : null,
                ]);

                if ($result->failed()) {
                    $errors[$key] = $result->getErrors();

                    // Dispatch rejection event
                    event(new FileUploadRejected(
                        $file->getClientOriginalName(),
                        $result->getErrors(),
                        $request->user(),
                        RequestContext::fromRequest($request)
                    ));
                }
            }
        }

        if (! empty($errors)) {
            return $this->validationErrorResponse($request, $errors);
        }

        // Attach validation results to request for downstream use
        $request->attributes->set('file_validation_passed', true);

        return $next($request);
    }

    /**
     * Get all uploaded files from the request.
     *
     * @return array<string, UploadedFile|UploadedFile[]>
     */
    protected function getAllUploadedFiles(Request $request): array
    {
        $files = [];

        foreach ($request->allFiles() as $key => $file) {
            if (is_array($file)) {
                foreach ($file as $index => $f) {
                    $files["{$key}.{$index}"] = $f;
                }
            } else {
                $files[$key] = $file;
            }
        }

        return $files;
    }

    /**
     * Calculate total size of all uploads.
     */
    protected function calculateTotalUploadSize(Request $request): int
    {
        $totalSize = 0;

        foreach ($request->allFiles() as $file) {
            if (is_array($file)) {
                foreach ($file as $f) {
                    if ($f instanceof UploadedFile) {
                        $totalSize += $f->getSize() ?: 0;
                    }
                }
            } elseif ($file instanceof UploadedFile) {
                $totalSize += $file->getSize() ?: 0;
            }
        }

        return $totalSize;
    }

    /**
     * Return rate limit exceeded response.
     */
    protected function rateLimitResponse(Request $request): Response
    {
        $retryAfter = $this->rateLimiter->availableIn($request);

        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Too many upload attempts. Please try again later.',
                'retry_after' => $retryAfter,
            ], 429)->header('Retry-After', $retryAfter);
        }

        return response('Too many upload attempts. Please try again later.', 429)
            ->header('Retry-After', $retryAfter);
    }

    /**
     * Return validation error response.
     */
    protected function validationErrorResponse(Request $request, array $errors): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'File validation failed.',
                'errors' => $errors,
            ], 422);
        }

        return redirect()
            ->back()
            ->withInput()
            ->withErrors($errors, 'file_upload');
    }
}
