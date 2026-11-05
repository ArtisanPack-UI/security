<?php

/**
 * Coverage for the XssProtection middleware.
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.2.0
 */

declare(strict_types=1);

use ArtisanPackUI\Security\Http\Middleware\XssProtection;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

function runXssProtection(array $input): Request
{
    $request = Request::create('/submit', 'POST', $input);

    (new XssProtection)->handle($request, fn (): Response => new Response('ok'));

    return $request;
}

test('it filters string input when enabled', function (): void {
    config()->set('artisanpack.security.xss.enabled', true);

    $request = runXssProtection([
        'bio' => '<p onclick="x()">Hi</p><script>alert(1)</script>',
        'nested' => ['body' => '<a href="javascript:alert(1)">x</a>'],
    ]);

    expect($request->input('bio'))->toBe('<p>Hi</p>alert(1)')
        ->and($request->input('nested.body'))->toBe('<a href="denied:javascript:alert(1)">x</a>');
});

test('it leaves credentials unchanged by default', function (): void {
    config()->set('artisanpack.security.xss.enabled', true);

    $password = 'pa<script>ss</script><b>word';

    $request = runXssProtection([
        'password' => $password,
        'password_confirmation' => $password,
        'current_password' => $password,
        'user' => ['password' => $password],
        'name' => '<script>x</script>',
    ]);

    expect($request->input('password'))->toBe($password)
        ->and($request->input('password_confirmation'))->toBe($password)
        ->and($request->input('current_password'))->toBe($password)
        ->and($request->input('user.password'))->toBe($password)
        ->and($request->input('name'))->toBe('x');
});

test('it honors a custom except list', function (): void {
    config()->set('artisanpack.security.xss.enabled', true);
    config()->set('artisanpack.security.xss.except', ['raw_html']);

    $request = runXssProtection([
        'raw_html' => '<script>x</script>',
        'password' => '<script>x</script>',
    ]);

    expect($request->input('raw_html'))->toBe('<script>x</script>')
        ->and($request->input('password'))->toBe('x');
});

test('it does nothing when disabled', function (): void {
    config()->set('artisanpack.security.xss.enabled', false);

    $request = runXssProtection(['bio' => '<script>x</script>']);

    expect($request->input('bio'))->toBe('<script>x</script>');
});
