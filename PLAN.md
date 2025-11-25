# Input Validation Framework Implementation Plan

This document outlines the plan to implement a comprehensive input validation and sanitization framework to prevent XSS and injection attacks.

## 1. Create Base FormRequest Class with Security Defaults

**Status:** Not started.

A new base `FormRequest` class will be created. This class will automatically sanitize the request data before the validation rules are applied.

**Action:**
- Create a new file: `src/Http/Requests/BaseFormRequest.php`.
- The `BaseFormRequest` will extend `Illuminate\Foundation\Http\FormRequest`.
- It will override the `validated()` method. Inside this method, it will iterate through all the validated data and apply a default sanitization policy.
- The default policy will use the existing `kses()` function (which uses `htmLawed`) with a strict configuration to remove any potentially harmful HTML.
- For specific fields that need to allow some HTML, developers will be able to override the sanitization rule for that field.

## 2. Implement XSS Protection Middleware

**Status:** Not started.

A middleware will be created to provide an additional layer of XSS protection by sanitizing the entire request body.

**Action:**
- Create a new file: `src/Http/Middleware/XssProtection.php`.
- The middleware will traverse the request input data (e.g., `request()->all()`) and apply the `kses()` function to all string values.
- This middleware will be registered in the `SecurityServiceProvider` and can be applied to routes or route groups. We will recommend applying it to all `web` routes.
- The middleware will be disabled by default and can be enabled in the `config/artisanpack/security.php` file.

## 3. Add Input Sanitization Utilities

**Status:** Mostly complete.

The project already has a good set of sanitization functions in `src/helpers.php` and the `Security` class. We will enhance this by adding a more configurable `sanitize` method.

**Action:**
- In the `Security` class, add a new public method `sanitize($data, $rules)`.
- This method will take an array of data and an array of rules. The rules will specify which sanitization function to apply to each field.
- For example, `['email' => 'email', 'bio' => 'html']`.
- If a rule is not specified for a field, a default of `sanitizeText` will be applied.
- The `'html'` rule will use the `kses` function.
- Add a corresponding `sanitize()` helper function in `src/helpers.php`.

## 4. Create Validation Rule Extensions for Security

**Status:** Not started.

We will create custom validation rules to enforce security best practices.

**Action:**
- Create a new directory `src/Rules`.
- Create the following validation rules:
    - `PasswordPolicy`: Enforces a strong password policy (e.g., length, complexity, not a common password). We can use a package like `kkomelin/laravel-pwned-password-validator` for checking against breached passwords.
    - `SecureUrl`: Validates that a URL is well-formed and does not use a dangerous scheme (e.g., `javascript:`).
    - `NoHtml`: A simple rule to ensure a string contains no HTML tags.
- These rules will be registered in the `SecurityServiceProvider`.

## 5. Implement File Upload Security Validation

**Status:** Not started.

We will add a custom validation rule for secure file uploads.

**Action:**
- Create a new validation rule: `src/Rules/SecureFile.php`.
- This rule will perform the following checks:
    - **MIME Type Validation:** It will use `finfo_file` or a similar method to check the *actual* MIME type of the file, not just the one provided by the client. It will accept a list of allowed MIME types.
    - **File Extension Check:** It will validate the file extension against a list of allowed extensions.
    - **File Size Check:** It will check the file size against a maximum size.
    - **ClamAV Integration (Optional):** We can add optional integration with ClamAV to scan for viruses. This will be disabled by default.

## 6. Add SQL Injection Prevention Helpers

**Status:** Mostly complete.

Laravel's Eloquent ORM and query builder already provide excellent protection against SQL injection by using parameterized queries. Attempting to manually detect SQL injection patterns in strings is unreliable and not recommended.

**Action:**
- We will not create new "helpers" to detect SQL injection.
- Instead, we will add a section to the documentation that explains how to use Laravel's existing features to prevent SQL injection.
- This documentation will emphasize the importance of *never* using raw SQL queries with user-provided data.

## 7. Create Validation Testing Utilities

**Status:** Not started.

We will create utilities to make it easier to test the new validation rules and `FormRequest` classes.

**Action:**
- Create a new testing trait: `tests/Concerns/ValidatesInput.php`.
- This trait will provide helper methods, such as `assertValidates` and `assertFailsValidation`.
- `assertValidates($rule, $value)` will assert that the given value passes the validation rule.
- `assertFailsValidation($rule, $value)` will assert that the given value fails the validation rule.
- We will also add tests for all the new rules and the `BaseFormRequest`.

## 8. Document Security Validation Patterns

**Status:** Not started.

A new documentation page will be created to explain the input validation framework.

**Action:**
- Create a new documentation file: `docs/input-validation.md`.
- This document will cover:
    - How to use the `BaseFormRequest`.
    - How to use the XSS protection middleware.
    - An overview of the sanitization utilities.
    - How to use the custom validation rules.
    - Best practices for file uploads.
    - How to prevent SQL injection using Laravel's built-in features.
- Update the main `README.md` or `home.md` to link to the new documentation page.
