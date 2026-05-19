# Configuration Management

The ArtisanPack UI Security package provides a comprehensive security configuration file that allows you to manage various security settings for your application. This document explains how to publish and manage this configuration, and how to use the provided tools to validate your setup.

## Publishing the Configuration

To publish the security configuration file, run the following Artisan command:

```bash
php artisan vendor:publish --tag=artisanpack-package-config
```

This will publish the `security.php` configuration file to your application's `config/artisanpack` directory. You can then customize the settings in this file to suit your needs.

## Configuration Validation

The package includes a service to validate your security configuration against best practices. This is especially important in production environments.

### Environment Validation Service

The `ArtisanPackUI\Security\Services\EnvironmentValidationService` is responsible for checking your configuration. In a production environment, it performs the following checks:

- **Debug Mode:** Ensures `app.debug` is `false`.
- **Session Encryption:** Ensures `artisanpack.security.encrypt` is `true`.
- **Two-Factor Authentication:** Warns if `artisanpack.security.enabled` is `false`.
- **Content Security Policy (CSP):** Warns if the CSP contains `'unsafe-inline'` or `'unsafe-eval'`.

### Production Environment Checks

These validation checks are run automatically when your application is in a production environment. Any errors or warnings are logged to the application's log file. Errors are logged as `critical`, and warnings as `warning`.

### Artisan Command

You can manually check your security configuration at any time using the `security:check-config` Artisan command:

```bash
php artisan security:check-config
```

This command will run the validation checks for your current environment and display the results in the console. If any errors are found, the command will exit with a non-zero status code, which can be useful for CI/CD pipelines.

## Configuration Caching

The security configuration fully supports Laravel's configuration caching. When you run `php artisan config:cache`, your `config/artisanpack/security.php` file will be cached along with the rest of your application's configuration. The package will correctly use the cached values.
