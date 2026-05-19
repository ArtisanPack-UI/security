# Migration Guide: Session Encryption

This guide outlines the changes related to session encryption in the ArtisanPack UI Security package. As of version 2.0, session encryption is enforced by default to enhance application security.

## Session Encryption by Default

Previously, session encryption was not actively enforced by this package. To mitigate security risks associated with unencrypted session data, session encryption is now enabled and verified by default in production environments.

### How to Disable Session Encryption

If you need to disable session encryption for a specific reason (which is strongly discouraged, especially in production), you can do so by setting the `SESSION_ENCRYPT` environment variable in your application's `.env` file:

```
SESSION_ENCRYPT=false
```

Disabling this in a production environment will throw a `RuntimeException` and prevent your application from running.

## New Artisan Command

A new Artisan command has been added to help you check the status of your session encryption:

```bash
php artisan security:check-session
```

This command will inform you whether session encryption is enabled or disabled. If it is disabled in a production environment, it will return an error.
