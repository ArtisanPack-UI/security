---
title: API Reference
---

# API Reference

Complete reference for all ArtisanPack UI Security functions. Each function is available both through the `Security` facade and as a global helper function.

## Sanitization Functions

### sanitizeEmail()

Cleans and validates email addresses by removing invalid characters.

**Usage:**
```php
Security::sanitizeEmail($email);
sanitizeEmail($email);
```

**Parameters:**
- `string|null $email` - Email address to sanitize

**Returns:** `string` - Cleaned email address

**Examples:**
```php
sanitizeEmail('goodÂ@bad.com');    // Returns: 'good@bad.com'
sanitizeEmail('<yo@marist.edu>');  // Returns: 'yo@marist.edu'
sanitizeEmail('mikeq@google.com'); // Returns: 'mikeq@google.com'
```

### sanitizeUrl()

Sanitizes URLs by removing invalid characters.

**Usage:**
```php
Security::sanitizeUrl($url);
sanitizeUrl($url);
```

**Parameters:**
- `string|null $url` - URL to sanitize

**Returns:** `string` - Cleaned URL

**Examples:**
```php
sanitizeUrl('goodÂ.com'); // Returns: 'good.com'
```

### sanitizeFilename()

Sanitizes filenames for safe file system usage.

**Usage:**
```php
Security::sanitizeFilename($filename);
sanitizeFilename($filename);
```

**Parameters:**
- `string|null $filename` - Filename to sanitize

**Returns:** `string` - Sanitized filename

**Examples:**
```php
sanitizeFilename('goodÂ.com'); // Returns: 'goodÂ.com'
```

### sanitizePassword()

Sanitizes password input while preserving necessary characters.

**Usage:**
```php
Security::sanitizePassword($password);
sanitizePassword($password);
```

**Parameters:**
- `string|null $password` - Password to sanitize

**Returns:** `string` - Sanitized password

### sanitizeInt()

Converts mixed input to a safe integer value.

**Usage:**
```php
Security::sanitizeInt($integer);
sanitizeInt($integer);
```

**Parameters:**
- `mixed $integer` - Value to convert to integer

**Returns:** `int` - Sanitized integer value

**Examples:**
```php
sanitizeInt('21');   // Returns: 21
sanitizeInt('24.3'); // Returns: 24
```

### sanitizeDate()

Normalizes date strings to a standard format.

**Usage:**
```php
Security::sanitizeDate($date);
sanitizeDate($date);
```

**Parameters:**
- `string|null $date` - Date string to sanitize

**Returns:** `string` - Normalized date in YYYY-MM-DD format

**Examples:**
```php
sanitizeDate('2025-02-02');     // Returns: '2025-02-02'
sanitizeDate('January 2, 2025'); // Returns: '2025-01-02'
```

### sanitizeDatetime()

Normalizes datetime strings to a standard format.

**Usage:**
```php
Security::sanitizeDatetime($datetime);
sanitizeDatetime($datetime);
```

**Parameters:**
- `string $datetime` - Datetime string to sanitize

**Returns:** `string` - Normalized datetime in YYYY-MM-DD HH:MM:SS format

**Examples:**
```php
sanitizeDatetime('2025-02-02 01:02:03');    // Returns: '2025-02-02 01:02:03'
sanitizeDatetime('January 2, 2025 3 p.m.'); // Returns: '2025-01-02 15:00:00'
```

### sanitizeFloat()

Converts and formats float values with specified decimal places.

**Usage:**
```php
Security::sanitizeFloat($float, $decimals);
sanitizeFloat($float, $decimals);
```

**Parameters:**
- `float $float` - Float value to sanitize
- `int $decimals` - Number of decimal places

**Returns:** `float` - Sanitized float value

### sanitizeArray()

Recursively sanitizes all values in an array.

**Usage:**
```php
Security::sanitizeArray($array);
sanitizeArray($array);
```

**Parameters:**
- `array $array` - Array to sanitize

**Returns:** `array` - Array with sanitized values

**Examples:**
```php
$input = [
    'name' => '<script>alert("xss")</script>John',
    'description' => '<p>This is a paragraph</p>'
];

$clean = sanitizeArray($input);
// Returns: ['name' => 'John', 'description' => 'This is a paragraph']
```

### sanitizeText()

Removes HTML tags and sanitizes text content.

**Usage:**
```php
Security::sanitizeText($text);
sanitizeText($text);
```

**Parameters:**
- `string|null $text` - Text to sanitize

**Returns:** `string` - Sanitized plain text

**Examples:**
```php
sanitizeText('<p>This is a paragraph</p>'); // Returns: 'This is a paragraph'
sanitizeText('January 2, 2025 3 p.m.');     // Returns: 'January 2, 2025 3 p.m.'
```

## Escaping Functions

### escHtml()

Escapes HTML characters to prevent XSS attacks in HTML context.

**Usage:**
```php
Security::escHtml($string);
escHtml($string);
```

**Parameters:**
- `string|null $string` - String to escape

**Returns:** `string` - HTML-escaped string

**Examples:**
```php
escHtml('<p>This is a paragraph</p>');
// Returns: '&lt;p&gt;This is a paragraph&lt;/p&gt;'
```

### escAttr()

Escapes strings for safe use in HTML attributes.

**Usage:**
```php
Security::escAttr($string);
escAttr($string);
```

**Parameters:**
- `string|null $string` - String to escape for attributes

**Returns:** `string` - Attribute-escaped string

**Examples:**
```php
escAttr('<p>This is a test</p>');
// Returns: '&lt;p&gt;This&#x20;is&#x20;a&#x20;test&lt;&#x2F;p&gt;'
```

### escUrl()

URL-encodes strings for safe use in URLs.

**Usage:**
```php
Security::escUrl($string);
escUrl($string);
```

**Parameters:**
- `string|null $string` - String to URL-encode

**Returns:** `string` - URL-encoded string

**Examples:**
```php
escUrl('https://ArtisanPackUIcms.com/this is a url');
// Returns: 'https%3A%2F%2FArtisanPackUIcms.com%2Fthis%20is%20a%20url'
```

### escJs()

Escapes strings for safe use in JavaScript contexts.

**Usage:**
```php
Security::escJs($string);
escJs($string);
```

**Parameters:**
- `string|null $string` - String to escape for JavaScript

**Returns:** `string` - JavaScript-escaped string

**Examples:**
```php
escJs('<script>let test = "";</script>');
// Returns: '\x3Cscript\x3Elet\x20test\x20\x3D\x20\x22\x22\x3B\x3C\x2Fscript\x3E'
```

### escCss()

Escapes strings for safe use in CSS contexts.

**Usage:**
```php
Security::escCss($string);
escCss($string);
```

**Parameters:**
- `string|null $string` - String to escape for CSS

**Returns:** `string` - CSS-escaped string

**Examples:**
```php
escCss('.class-name {background-color: #000000;}');
// Returns: '\2E class\2D name\20 \7B background\2D color\3A \20 \23 000000\3B \7D '
```

## HTML Filtering

### kses()

WordPress-style HTML filtering that allows safe HTML while removing potentially dangerous tags and attributes.

**Usage:**
```php
Security::kses($html, $config, $spec);
kses($html);
```

**Parameters:**
- `string $html` - HTML string to filter
- `mixed $config` - Configuration for allowed tags (optional)
- `mixed $spec` - Specification for filtering rules (optional)

**Returns:** `string` - Filtered HTML

**Examples:**
```php
$html = '<div class="test-div"><p>Safe content</p><script>alert("xss")</script></div>';
$safe = kses($html);
// Returns: '<div class="test-div"><p>Safe content</p></div>'
```

## Security Helper

### security()

Returns the Security service instance for advanced usage.

**Usage:**
```php
security()
```

**Returns:** `Security` - Security service instance

**Examples:**
```php
$securityService = security();
$clean = $securityService->sanitizeText($input);
```