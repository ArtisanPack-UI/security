<?php

/**
 * Coverage for the extension hooks exposed by the Security package.
 *
 * Each hook registers a subscriber, exercises the code path that fires
 * it, and asserts both the payload and the ability to mutate the result
 * (for filters) or observe a side effect (for actions).
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.1.0
 */

declare(strict_types=1);

namespace Tests\Feature;

use ArtisanPackUI\Security\Contracts\CspPolicyInterface;
use ArtisanPackUI\Security\Models\CspViolationReport;
use ArtisanPackUI\Security\Security;
use ArtisanPackUI\Security\Services\Csp\CspViolationHandler;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class HooksTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        removeAllFilters('ap.security.sanitizedInput');
        removeAllFilters('ap.security.escapedOutput');
        removeAllFilters('ap.security.ksesAllowedTags');
        removeAllFilters('ap.security.csp.directives');
        removeAllActions('ap.security.csp.violationHandled');

        parent::tearDown();
    }

    #[Test]
    public function sanitized_input_filter_receives_value_type_and_original(): void
    {
        $captured = [];

        addFilter('ap.security.sanitizedInput', function (mixed $value, string $type, mixed $original) use (&$captured): mixed {
            $captured[] = ['value' => $value, 'type' => $type, 'original' => $original];

            return $value;
        });

        $security = new Security;
        $security->sanitizeText('<p>hello</p>');

        $this->assertCount(1, $captured);
        $this->assertSame('hello', $captured[0]['value']);
        $this->assertSame('text', $captured[0]['type']);
        $this->assertSame('<p>hello</p>', $captured[0]['original']);
    }

    #[Test]
    public function sanitized_input_filter_can_mutate_the_return_value(): void
    {
        addFilter('ap.security.sanitizedInput', function (mixed $value, string $type): mixed {
            if ($type === 'email') {
                return strtoupper((string) $value);
            }

            return $value;
        });

        $security = new Security;

        $this->assertSame('USER@EXAMPLE.COM', $security->sanitizeEmail('user@example.com'));
    }

    #[Test]
    public function sanitized_input_filter_fires_for_every_sanitizer(): void
    {
        $seenTypes = [];

        addFilter('ap.security.sanitizedInput', function (mixed $value, string $type) use (&$seenTypes): mixed {
            $seenTypes[] = $type;

            return $value;
        });

        $security = new Security;
        $security->sanitizeEmail('user@example.com');
        $security->sanitizeUrl('https://example.com');
        $security->sanitizeFilename('report.pdf');
        $security->sanitizePassword('hunter2');
        $security->sanitizeInt('42');
        $security->sanitizeDate('2026-01-15');
        $security->sanitizeDatetime('2026-01-15 12:30:00');
        $security->sanitizeFloat(1.234, 2);
        $security->sanitizeText('plain');
        $security->sanitizeArray(['a', 'b']);

        $this->assertCount(12, $seenTypes);
        $this->assertEqualsCanonicalizing(
            ['email', 'url', 'filename', 'password', 'int', 'date', 'datetime', 'float', 'text', 'text', 'text', 'array'],
            $seenTypes,
        );
    }

    #[Test]
    public function no_subscribers_leaves_sanitize_and_escape_output_unchanged(): void
    {
        $security = new Security;

        $this->assertSame('user@example.com', $security->sanitizeEmail('user@example.com'));
        $this->assertSame('This is text', $security->sanitizeText('<p>This is text</p>'));
        $this->assertSame('&lt;script&gt;alert(1)&lt;/script&gt;', $security->escHtml('<script>alert(1)</script>'));
        $this->assertSame(42, $security->sanitizeInt('42'));
        $this->assertSame(1.23, $security->sanitizeFloat(1.234, 2));
    }

    #[Test]
    public function escaped_output_filter_receives_value_context_and_original(): void
    {
        $captured = [];

        addFilter('ap.security.escapedOutput', function (string $value, string $context, string $original) use (&$captured): string {
            $captured[] = ['value' => $value, 'context' => $context, 'original' => $original];

            return $value;
        });

        $security = new Security;
        $security->escHtml('<script>alert(1)</script>');

        $this->assertCount(1, $captured);
        $this->assertSame('html', $captured[0]['context']);
        $this->assertSame('<script>alert(1)</script>', $captured[0]['original']);
        $this->assertStringContainsString('&lt;script&gt;', $captured[0]['value']);
    }

    #[Test]
    public function escaped_output_filter_can_mutate_the_return_value(): void
    {
        addFilter('ap.security.escapedOutput', function (string $value, string $context): string {
            if ($context === 'html') {
                return '<!-- filtered -->'.$value;
            }

            return $value;
        });

        $security = new Security;

        $this->assertStringStartsWith('<!-- filtered -->', $security->escHtml('hi'));
    }

    #[Test]
    public function escaped_output_filter_fires_for_every_escaper(): void
    {
        $seenContexts = [];

        addFilter('ap.security.escapedOutput', function (string $value, string $context) use (&$seenContexts): string {
            $seenContexts[] = $context;

            return $value;
        });

        $security = new Security;
        $security->escHtml('a');
        $security->escAttr('b');
        $security->escUrl('https://example.com');
        $security->escJs('c');
        $security->escCss('d');

        $this->assertSame(['html', 'attr', 'url', 'js', 'css'], $seenContexts);
    }

    #[Test]
    public function kses_allowed_tags_filter_restricts_the_element_whitelist(): void
    {
        addFilter('ap.security.ksesAllowedTags', function (array $allowedTags): array {
            return ['strong', 'em'];
        });

        $security = new Security;
        $result = $security->kses('<strong>bold</strong><script>alert(1)</script><em>ital</em>');

        $this->assertStringContainsString('<strong>bold</strong>', $result);
        $this->assertStringContainsString('<em>ital</em>', $result);
        $this->assertStringNotContainsString('<script', $result);
    }

    #[Test]
    public function kses_allowed_tags_filter_receives_an_empty_starting_array(): void
    {
        $received = null;

        addFilter('ap.security.ksesAllowedTags', function (array $allowedTags) use (&$received): array {
            $received = $allowedTags;

            return $allowedTags;
        });

        $security = new Security;
        $security->kses('<p>hello</p>');

        $this->assertSame([], $received);
    }

    #[Test]
    public function kses_allowed_tags_filter_is_bypassed_when_caller_passes_non_default_config(): void
    {
        $called = false;

        addFilter('ap.security.ksesAllowedTags', function (array $allowedTags) use (&$called): array {
            $called = true;

            return ['strong'];
        });

        $security = new Security;
        $security->kses('<p>hello</p>', 2);
        $security->kses('<p>hello</p>', ['elements' => 'p,a']);

        $this->assertFalse($called, 'ksesAllowedTags subscribers must not run when the caller specifies non-default $config.');
    }

    #[Test]
    public function csp_directives_filter_can_add_directives(): void
    {
        addFilter('ap.security.csp.directives', function (array $directives, Request $request): array {
            $directives['img-src'] = ['https://cdn.example.com'];

            return $directives;
        });

        $service = app(CspPolicyInterface::class);
        $service->reset();
        $service->forRequest(Request::create('/test', 'GET'));

        $policy = $service->getPolicy();

        $this->assertStringContainsString('img-src https://cdn.example.com', $policy);
    }

    #[Test]
    public function csp_directives_filter_receives_current_request(): void
    {
        $captured = null;

        addFilter('ap.security.csp.directives', function (array $directives, Request $request) use (&$captured): array {
            $captured = $request;

            return $directives;
        });

        $service = app(CspPolicyInterface::class);
        $service->reset();
        $service->forRequest(Request::create('/csp-test-path', 'GET'));
        $service->getPolicy();

        $this->assertInstanceOf(Request::class, $captured);
        $this->assertSame('csp-test-path', $captured->path());
    }

    #[Test]
    public function csp_violation_handled_action_receives_the_report(): void
    {
        Config::set('artisanpack.security.csp.reporting.storeViolations', true);
        Config::set('artisanpack.security.csp.reporting.logToSecurityEvents', false);

        $captured = null;

        addAction('ap.security.csp.violationHandled', function (CspViolationReport $report) use (&$captured): void {
            $captured = $report;
        });

        $handler = app(CspViolationHandler::class);
        $handler->handle([
            'csp-report' => [
                'document-uri' => 'https://example.com/page',
                'blocked-uri' => 'https://evil.example.com/script.js',
                'violated-directive' => 'script-src',
            ],
        ]);

        $this->assertInstanceOf(CspViolationReport::class, $captured);
        $this->assertSame('script-src', $captured->violated_directive);
        $this->assertSame('https://evil.example.com/script.js', $captured->blocked_uri);
    }
}
