# Input Validation

The ArtisanPack UI Security package provides a robust framework for validating and sanitizing user input to prevent common vulnerabilities like Cross-Site Scripting (XSS) and SQL injection.

## FormRequest Sanitization

It is highly recommended that you create form request classes for all of your forms that handle user input. You can extend the `ArtisanPackUI\Security\Http\Requests\BaseFormRequest` class to automatically sanitize your request data.

### Default Sanitization

By default, all string data in a `BaseFormRequest` is sanitized using the `sanitizeText()` helper, which removes all HTML tags.

### Customizing Sanitization

You can customize the sanitization rules for each field by defining a `sanitizationRules` property on your form request:

```php
use ArtisanPackUI\Security\Http\Requests\BaseFormRequest;

class MyFormRequest extends BaseFormRequest
{
    protected $sanitizationRules = [
        'bio' => 'html',
        'email' => 'email',
        'website' => 'url',
    ];

    public function rules()
    {
        return [
            'bio' => 'required|string',
            'email' => 'required|email',
            'website' => 'required|url',
        ];
    }
}
```

The available sanitization rules are: `text`, `html`, `email`, `url`, and `filename`.

## XSS Protection Middleware

The package includes an `XssProtection` middleware that can be applied to your routes to automatically sanitize the entire request body. This provides an additional layer of defense against XSS attacks.

To enable the middleware, first add it to your `app/Http/Kernel.php`:

```php
protected $middlewareGroups = [
    'web' => [
        // ...
        \ArtisanPackUI\Security\Http\Middleware\XssProtection::class,
    ],
    // ...
];
```

Then, enable it in your `config/artisanpack/security.php` file:

```php
'xss' => [
    'enabled' => true,
],
```

## Custom Validation Rules

The package provides several custom validation rules for enhanced security.

### Password Policy

The `password_policy` rule enforces a strong password policy. It checks for:
- Minimum length of 8 characters
- At least one letter
- A mix of uppercase and lowercase letters
- At least one number
- At least one symbol
- That the password has not been exposed in a public data breach (using the Have I Been Pwned database).

**Usage:**
```php
'password' => ['required', 'confirmed', 'password_policy']
```

### Secure URL

The `secure_url` rule validates that a field is a valid URL and uses a secure scheme (`http` or `https`).

**Usage:**
```php
'website' => ['required', 'secure_url']
```

### No HTML

The `no_html` rule validates that a field does not contain any HTML tags.

**Usage:**
```php
'username' => ['required', 'no_html']
```

### Secure File

The `secure_file` rule provides validation for file uploads.

**Usage:**
```php
'avatar' => ['required', 'secure_file:image/png,image/jpeg,2048']
```
The parameters are:
1.  A comma-separated list of allowed MIME types.
2.  The maximum file size in kilobytes.

## SQL Injection Prevention

Laravel's Eloquent ORM and query builder provide excellent protection against SQL injection out of the box by using parameterized queries. **You should never use raw SQL queries with user-provided data.**

Always use Eloquent or the query builder to interact with your database:

```php
// Good: Uses parameter binding
$users = DB::table('users')->where('email', $request->email)->get();

// Bad: Vulnerable to SQL injection
$users = DB::select("SELECT * FROM users WHERE email = '{$request->email}'");
```
