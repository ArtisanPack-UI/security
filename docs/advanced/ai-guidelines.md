---
title: AI Guidelines for Security
---

# AI Guidelines for Security

## ArtisanPack UI Security Package

**Primary Goal:** To ensure that all generated code is secure by default and follows Laravel security best practices.

### Core Principles for the AI:

- **Input Sanitization:** Sanitize all data received from users or external sources to prevent common vulnerabilities.

- **Output Escaping:** Escape all data before rendering it in the browser to prevent Cross-Site Scripting (XSS) attacks.

- **Secure by Default:** Adhere to Laravel's built-in security features, such as CSRF protection and parameterized queries.

### Specific Instructions for the AI:

- When generating code that handles user input, use the appropriate sanitization functions from the Security class, such as `sanitizeEmail`, `sanitizeText`, and `sanitizeInt`.

- When displaying user-generated content in Blade views, use the appropriate escaping functions, such as `escHtml` and `escAttr`, to prevent XSS attacks.

- For all database interactions, use Laravel's Eloquent ORM or the query builder with parameterized queries to prevent SQL injection vulnerabilities.

- When generating HTML forms, always include the `@csrf` Blade directive to protect against Cross-Site Request Forgery attacks.