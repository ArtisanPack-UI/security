## ArtisanPack UI Security

This package provides comprehensive data sanitization and output escaping functions to protect Laravel applications against XSS attacks, SQL injection, and data corruption. It also includes robust two-factor authentication (2FA) capabilities.

### Core Security Principles

- **Always sanitize user input** before processing or storing data
- **Always escape output** before rendering in views to prevent XSS attacks
- **Use context-aware escaping** for different output contexts (HTML, attributes, URLs, JS, CSS)
- **Never trust user input** - treat all external data as potentially malicious

### Input Sanitization

Use sanitization functions when receiving data from users, forms, APIs, or any external source:

@verbatim
	<code-snippet name="Sanitize user input" lang="php">
		use ArtisanPackUI\Security\Facades\Security;

		// Sanitize email addresses
		$cleanEmail = Security::sanitizeEmail($request->input('email'));

		// Sanitize text (removes HTML tags)
		$cleanText = Security::sanitizeText($request->input('comment'));

		// Sanitize integers
		$cleanId = Security::sanitizeInt($request->input('user_id'));

		// Sanitize URLs
		$cleanUrl = Security::sanitizeUrl($request->input('website'));

		// Or use global helper functions
		$cleanEmail = sanitizeEmail($request->input('email'));
		$cleanText = sanitizeText($request->input('comment'));
	</code-snippet>
@endverbatim

Available sanitization functions:
- `sanitizeEmail()` - Clean and validate email addresses
- `sanitizeUrl()` - Sanitize and validate URLs
- `sanitizeText()` - Remove HTML tags and clean text
- `sanitizeInt()` - Convert to safe integers
- `sanitizeFloat()` - Convert to safe floats
- `sanitizeDate()` - Sanitize date strings
- `sanitizeDatetime()` - Sanitize datetime strings
- `sanitizeFilename()` - Clean filename strings
- `sanitizePassword()` - Sanitize password input
- `sanitizeArray()` - Recursively sanitize arrays

### Output Escaping

Always escape data before displaying it in views, especially user-generated content:

@verbatim
	<code-snippet name="Escape output in Blade views" lang="blade">
		{{-- Escape HTML content --}}
		<div class="comment">
			{!! escHtml($userComment) !!}
		</div>

		{{-- Escape HTML attributes --}}
		<input type="text" value="{{ escAttr($userInput) }}"/>
		<a href="{{ escUrl($userProvidedUrl) }}" title="{{ escAttr($userTitle) }}">Link</a>

		{{-- Escape JavaScript context --}}
		<script>
            var userName = '{{ escJs($user->name) }}';
		</script>

		{{-- Escape CSS context --}}
		<style>
            .user-color {
                color: {{ escCss($userColor) }};
            }
		</style>
	</code-snippet>
@endverbatim

Available escaping functions:
- `escHtml()` - Escape for HTML body content
- `escAttr()` - Escape for HTML attributes
- `escUrl()` - Escape for URLs
- `escJs()` - Escape for JavaScript contexts
- `escCss()` - Escape for CSS contexts

### HTML Filtering

Use `kses()` for WordPress-style HTML filtering when you need to allow some HTML but want to sanitize it:

@verbatim
	<code-snippet name="Filter HTML content" lang="php">
		// Allow only safe HTML tags
		$safeHtml = kses($userContent);

		// Display in view
		<div class="content">
			{!! kses($userContent) !!}
		</div>
	</code-snippet>
@endverbatim

### Two-Factor Authentication

Implement 2FA with email codes or Google Authenticator/TOTP:

@verbatim
	<code-snippet name="Implement two-factor authentication" lang="php">
		use ArtisanPackUI\Security\Facades\TwoFactor;
		use ArtisanPackUI\Security\TwoFactor\TwoFactorAuthenticatable;

		// 1. Add trait to User model
		class User extends Authenticatable
		{
		use TwoFactorAuthenticatable;

		// Add these columns to users table migration:
		// $table->text('two_factor_secret')->nullable();
		// $table->text('two_factor_recovery_codes')->nullable();
		// $table->timestamp('two_factor_enabled_at')->nullable();
		}

		// 2. Enable 2FA for a user
		TwoFactor::enable($user);

		// 3. Generate and send challenge (after login)
		TwoFactor::generateChallenge($user);

		// 4. Verify the code
		if (TwoFactor::verify($user, $request->input('code'))) {
		// User authenticated successfully
		}

		// 5. Switch provider (email or google2fa)
		TwoFactor::setProvider('google2fa');
	</code-snippet>
@endverbatim

**Required for 2FA:**
- Create route named `two-factor.challenge` for code entry
- Create view for 2FA code input form
- Add required database columns to users table
- Add `TwoFactorAuthenticatable` trait to User model

### Session Security

Enable encrypted sessions for enhanced security:

@verbatim
	<code-snippet name="Enable session encryption" lang="php">
		// Add to app/Http/Kernel.php
		protected $middleware = [
		\ArtisanPackUI\Security\Http\Middleware\EnsureSessionIsEncrypted::class,
		];

		// Check session security status
		php artisan security:check-session
	</code-snippet>
@endverbatim

### Best Practices

- **Controller Layer**: Sanitize input as early as possible (in form requests or controllers)
- **View Layer**: Always escape output, even if you think the data is safe
- **Database Layer**: Use Eloquent ORM or Query Builder with parameter binding (Laravel handles this)
- **Forms**: Always include `@csrf` directive in forms
- **API Responses**: Escape data before returning in JSON responses when needed
- **Validation**: Combine sanitization with Laravel's validation rules for robust security
