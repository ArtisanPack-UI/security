---
title: Getting Started with ArtisanPack UI Security
---

# Getting Started

The ArtisanPack UI Security package provides essential security functions for Laravel applications, specifically designed for the Digital Shopfront CMS. It offers comprehensive data sanitization and output escaping functions to protect against common web vulnerabilities.

## Installation

Install the package via Composer:

```bash
composer require ArtisanPackUI/security
```

## Basic Usage

The package provides two ways to use the security functions:

### Using the Security Facade

```php
use ArtisanPackUI\Security\Facades\Security;

// Sanitize user input
$cleanEmail = Security::sanitizeEmail($userEmail);
$cleanText = Security::sanitizeText($userInput);

// Escape output for safe rendering
echo Security::escHtml($userContent);
```

### Using Global Helper Functions

```php
// Sanitize user input
$cleanEmail = sanitizeEmail($userEmail);
$cleanText = sanitizeText($userInput);

// Escape output for safe rendering
echo escHtml($userContent);
```

## Common Use Cases

### Sanitizing User Input

```php
// Clean email addresses
$email = sanitizeEmail('goodÂ@bad.com'); // Returns: 'good@bad.com'

// Clean text content
$text = sanitizeText('<p>Hello World</p>'); // Returns: 'Hello World'

// Sanitize integers
$number = sanitizeInt('42.7'); // Returns: 42

// Clean arrays recursively
$data = sanitizeArray([
    'name' => '<script>alert("xss")</script>John',
    'email' => 'john@example.com'
]);
```

### Escaping Output

```php
// In Blade templates
<div>{{ escHtml($userContent) }}</div>
<img src="image.jpg" alt="{{ escAttr($userTitle) }}">
<a href="{{ escUrl($userUrl) }}">Link</a>

// In JavaScript contexts
<script>
    var userData = {!! escJs($jsonData) !!};
</script>

// In CSS contexts
<style>
    .user-class { content: {{ escCss($userContent) }}; }
</style>
```

### HTML Filtering with Kses

The `kses` function provides WordPress-style HTML filtering:

```php
$safeHtml = kses($userHtml);
// Allows safe HTML tags while removing potentially dangerous ones
```

## Security Best Practices

1. **Always sanitize input**: Clean all user data before processing or storing
2. **Always escape output**: Escape data before rendering in HTML, attributes, URLs, JS, or CSS
3. **Use appropriate functions**: Choose the right sanitization/escaping function for your context
4. **Layer your security**: Combine multiple security measures for defense in depth

## Next Steps

- Explore the complete [API Reference](api-reference) for detailed function documentation
- Read the [Security Guidelines](security-guidelines) for advanced security practices
- Check out the [AI Guidelines](ai-guidelines) if you're using AI code generation