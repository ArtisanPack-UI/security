---
title: Security Guidelines
---

# Security Guidelines

This guide provides comprehensive security best practices for using the ArtisanPack UI Security package effectively to protect your Laravel applications against common web vulnerabilities.

## Core Security Principles

### 1. Input Validation and Sanitization

Always validate and sanitize data received from users or external sources:

```php
// Validate before sanitizing
if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $cleanEmail = sanitizeEmail($email);
} else {
    // Handle invalid email
    throw new InvalidArgumentException('Invalid email format');
}

// Sanitize all user input
$userData = [
    'name' => sanitizeText($_POST['name']),
    'email' => sanitizeEmail($_POST['email']),
    'age' => sanitizeInt($_POST['age']),
    'bio' => sanitizeText($_POST['bio'])
];
```

### 2. Output Escaping

Always escape data before rendering it in different contexts:

```php
// HTML context
echo escHtml($userContent);

// HTML attribute context
echo '<img alt="' . escAttr($userTitle) . '">';

// URL context
echo '<a href="' . escUrl($userUrl) . '">Link</a>';

// JavaScript context
echo '<script>var data = ' . escJs($jsonData) . ';</script>';

// CSS context
echo '<style>.class { content: ' . escCss($userContent) . '; }</style>';
```

## Vulnerability Prevention

### Cross-Site Scripting (XSS) Prevention

XSS attacks occur when malicious scripts are injected into web pages. Use appropriate escaping functions:

```php
// Prevent XSS in HTML content
$safeContent = escHtml($userContent);

// Prevent XSS in HTML attributes
$safeAttribute = escAttr($userAttribute);

// For rich content that needs some HTML, use kses
$safeHtml = kses($userHtml);
```

**Bad:**
```php
echo '<div>' . $userInput . '</div>'; // Vulnerable to XSS
```

**Good:**
```php
echo '<div>' . escHtml($userInput) . '</div>'; // Safe from XSS
```

### SQL Injection Prevention

While this package doesn't directly handle database queries, proper input sanitization helps:

```php
// Sanitize before database operations
$userId = sanitizeInt($_GET['id']);
$userName = sanitizeText($_POST['name']);

// Use with Laravel's query builder or Eloquent (which uses parameterized queries)
User::where('id', $userId)->where('name', $userName)->first();
```

### CSRF Protection

Always include CSRF protection in forms when handling user input:

```blade
<form method="POST" action="/user/update">
    @csrf
    <input type="text" name="name" value="{{ escAttr($user->name) }}">
    <textarea name="bio">{{ escHtml($user->bio) }}</textarea>
    <button type="submit">Update</button>
</form>
```

## Context-Specific Security

### Database Context

```php
// Sanitize before storing
$user = new User();
$user->name = sanitizeText($request->name);
$user->email = sanitizeEmail($request->email);
$user->age = sanitizeInt($request->age);
$user->save();
```

### File Handling Context

```php
// Sanitize filenames before file operations
$filename = sanitizeFilename($uploadedFile->getClientOriginalName());
$path = storage_path('uploads/' . $filename);

// Additional file security checks
if (!in_array($uploadedFile->getClientMimeType(), ['image/jpeg', 'image/png'])) {
    throw new InvalidArgumentException('Invalid file type');
}
```

### API Responses

```php
// Sanitize data before JSON responses
$responseData = [
    'user' => [
        'name' => sanitizeText($user->name),
        'email' => sanitizeEmail($user->email),
        'bio' => sanitizeText($user->bio)
    ]
];

return response()->json($responseData);
```

## Advanced Security Practices

### Defense in Depth

Layer multiple security measures:

```php
class UserController extends Controller
{
    public function store(Request $request)
    {
        // 1. Validate input structure
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users',
            'bio' => 'nullable|string|max:1000'
        ]);

        // 2. Sanitize input
        $userData = [
            'name' => sanitizeText($request->name),
            'email' => sanitizeEmail($request->email),
            'bio' => sanitizeText($request->bio)
        ];

        // 3. Create user with sanitized data
        $user = User::create($userData);

        // 4. Escape output
        return view('user.profile', [
            'name' => escHtml($user->name),
            'email' => escHtml($user->email),
            'bio' => escHtml($user->bio)
        ]);
    }
}
```

### Content Security Policy (CSP)

Implement CSP headers alongside output escaping:

```php
// In your middleware or controller
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'");
```

### HTML Filtering Best Practices

When using `kses()` for rich content:

```php
// Allow only safe HTML tags
$allowedTags = [
    'p' => [],
    'br' => [],
    'strong' => [],
    'em' => [],
    'ul' => [],
    'ol' => [],
    'li' => []
];

$safeContent = kses($userContent, $allowedTags);
```

## Common Security Mistakes

### ❌ Don't Do This

```php
// Never trust user input directly
echo $_POST['content']; // Vulnerable to XSS

// Don't escape already escaped content
echo escHtml(escHtml($content)); // Double escaping

// Don't use wrong escaping context
echo '<script>var data = "' . escHtml($data) . '";</script>'; // Should use escJs

// Don't sanitize display data
$displayName = sanitizeText($user->name); // Only sanitize on input
```

### ✅ Do This Instead

```php
// Always escape output appropriately
echo escHtml($_POST['content']);

// Escape once, in the right context
echo escHtml($content);

// Use correct escaping for context
echo '<script>var data = ' . escJs($data) . ';</script>';

// Sanitize on input, escape on output
// Input: sanitizeText() -> Store in DB
// Output: escHtml() -> Display to user
```

## Security Checklist

### Input Handling
- [ ] Validate all user input with Laravel validation rules
- [ ] Sanitize input before storing in database
- [ ] Use appropriate sanitization function for data type
- [ ] Implement rate limiting for forms

### Output Handling
- [ ] Escape all output with appropriate function
- [ ] Use `escHtml()` for HTML content
- [ ] Use `escAttr()` for HTML attributes
- [ ] Use `escUrl()` for URLs
- [ ] Use `escJs()` for JavaScript contexts
- [ ] Use `escCss()` for CSS contexts

### General Security
- [ ] Include CSRF protection on all forms
- [ ] Implement Content Security Policy
- [ ] Use HTTPS in production
- [ ] Keep dependencies updated
- [ ] Implement proper error handling
- [ ] Log security-related events

## Testing Security

Always test your security implementations:

```php
// Test XSS prevention
$maliciousInput = '<script>alert("XSS")</script>';
$safeOutput = escHtml($maliciousInput);
assert($safeOutput === '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');

// Test input sanitization
$dirtyEmail = '<script>bad@email.com';
$cleanEmail = sanitizeEmail($dirtyEmail);
assert($cleanEmail === 'bad@email.com');
```

## Emergency Response

If you discover a security vulnerability:

1. **Don't panic** - Document the issue carefully
2. **Assess impact** - Determine affected systems and data
3. **Apply immediate fixes** - Use security functions to patch
4. **Monitor logs** - Check for exploitation attempts
5. **Update documentation** - Record lessons learned

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Laravel Security Best Practices](https://laravel.com/docs/security)
- [PHP Security Guidelines](https://www.php.net/manual/en/security.php)

For AI-specific security guidelines, see [AI Guidelines](ai-guidelines).