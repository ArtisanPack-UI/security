---
title: Environment Variables Reference
---

# Environment Variables Reference

Complete reference for all environment variables used by the ArtisanPack Security package.

## Quick Reference

Copy these to your `.env` file and customize as needed:

```env
# Core Security
SECURITY_ENABLED=true

# Authentication
SECURITY_AUTH_ENABLED=true
SECURITY_DEVICE_FINGERPRINTING_ENABLED=true

# Two-Factor Authentication
SECURITY_2FA_ENABLED=true

# Password Security
SECURITY_PASSWORD_ENABLED=true
SECURITY_HIBP_ENABLED=true

# API Security
SECURITY_API_ENABLED=true
SECURITY_API_TOKEN_EXPIRATION=365

# Session Security
SECURITY_ADVANCED_SESSIONS_ENABLED=true
SECURITY_STEP_UP_ENABLED=true

# CSP
SECURITY_CSP_ENABLED=true
SECURITY_CSP_REPORT_ONLY=false

# Headers
SECURITY_HEADERS_ENABLED=true

# File Upload
SECURITY_FILE_UPLOAD_ENABLED=true
SECURITY_MALWARE_SCANNING_ENABLED=false
SECURITY_MALWARE_DRIVER=null

# RBAC
SECURITY_RBAC_ENABLED=true

# Compliance
SECURITY_COMPLIANCE_ENABLED=true

# Analytics
SECURITY_ANALYTICS_ENABLED=true

# Logging
SECURITY_LOGGING_ENABLED=true
SECURITY_LOG_CHANNEL=security
```

---

## Core Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_ENABLED` | bool | `true` | Master switch for all security features |

---

## Authentication

### General Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_AUTH_ENABLED` | bool | `true` | Enable authentication features |
| `SECURITY_DEVICE_FINGERPRINTING_ENABLED` | bool | `true` | Enable device fingerprinting |

### Social Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_SOCIAL_AUTH_ENABLED` | bool | `false` | Enable social login |
| `SECURITY_SOCIAL_GOOGLE_ENABLED` | bool | `false` | Enable Google login |
| `SECURITY_SOCIAL_MICROSOFT_ENABLED` | bool | `false` | Enable Microsoft login |
| `SECURITY_SOCIAL_GITHUB_ENABLED` | bool | `false` | Enable GitHub login |
| `SECURITY_SOCIAL_FACEBOOK_ENABLED` | bool | `false` | Enable Facebook login |
| `SECURITY_SOCIAL_APPLE_ENABLED` | bool | `false` | Enable Apple login |
| `SECURITY_SOCIAL_LINKEDIN_ENABLED` | bool | `false` | Enable LinkedIn login |

### Social Provider Credentials

```env
# Google
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Microsoft
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_TENANT=common

# GitHub
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Facebook
FACEBOOK_CLIENT_ID=
FACEBOOK_CLIENT_SECRET=

# Apple
APPLE_CLIENT_ID=
APPLE_CLIENT_SECRET=
APPLE_TEAM_ID=
APPLE_KEY_ID=

# LinkedIn
LINKEDIN_CLIENT_ID=
LINKEDIN_CLIENT_SECRET=
```

### SSO Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_SSO_ENABLED` | bool | `false` | Enable SSO features |
| `SECURITY_SAML_ENABLED` | bool | `false` | Enable SAML authentication |
| `SECURITY_OIDC_ENABLED` | bool | `false` | Enable OIDC authentication |
| `SECURITY_LDAP_ENABLED` | bool | `false` | Enable LDAP authentication |

### SAML Configuration

```env
SAML_IDP_ENTITY_ID=
SAML_IDP_SSO_URL=
SAML_IDP_SLO_URL=
SAML_IDP_CERTIFICATE=

SAML_SP_ENTITY_ID=
SAML_SP_ACS_URL=
SAML_SP_SLS_URL=
SAML_SP_CERTIFICATE=
SAML_SP_PRIVATE_KEY=
```

### OIDC Configuration

```env
OIDC_ISSUER=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
OIDC_REDIRECT_URI=
```

### LDAP Configuration

```env
LDAP_HOST=ldap.example.com
LDAP_PORT=389
LDAP_BASE_DN=
LDAP_USERNAME=
LDAP_PASSWORD=
LDAP_SSL=false
LDAP_TLS=true
```

### WebAuthn Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_WEBAUTHN_ENABLED` | bool | `false` | Enable WebAuthn/Passkeys |
| `WEBAUTHN_RP_ID` | string | - | Relying party ID (domain) |

### Biometric Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_BIOMETRIC_ENABLED` | bool | `false` | Enable biometric auth |

---

## Two-Factor Authentication

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_2FA_ENABLED` | bool | `true` | Enable 2FA features |

### SMS 2FA (Twilio)

```env
TWILIO_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM=
```

---

## Password Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_PASSWORD_ENABLED` | bool | `true` | Enable password security |
| `SECURITY_HIBP_ENABLED` | bool | `true` | Enable Have I Been Pwned checking |

---

## API Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_API_ENABLED` | bool | `true` | Enable API security features |
| `SECURITY_API_TOKEN_EXPIRATION` | int | `365` | Token expiration in days |

---

## Session Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_ADVANCED_SESSIONS_ENABLED` | bool | `true` | Enable advanced session security |
| `SECURITY_STEP_UP_ENABLED` | bool | `true` | Enable step-up authentication |

### Laravel Session Settings

These are standard Laravel settings that affect security:

```env
SESSION_DRIVER=database
SESSION_LIFETIME=120
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=true
SESSION_SAME_SITE=lax
SESSION_HTTP_ONLY=true
```

---

## Content Security Policy

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_CSP_ENABLED` | bool | `true` | Enable CSP headers |
| `SECURITY_CSP_REPORT_ONLY` | bool | `false` | Use report-only mode |
| `CSP_PROFILE` | string | `'production'` | Active CSP profile |

---

## Security Headers

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_HEADERS_ENABLED` | bool | `true` | Enable security headers |

---

## File Upload Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_FILE_UPLOAD_ENABLED` | bool | `true` | Enable file upload security |
| `SECURITY_MALWARE_SCANNING_ENABLED` | bool | `false` | Enable malware scanning |
| `SECURITY_MALWARE_DRIVER` | string | `'null'` | Malware scanner driver |

### VirusTotal Integration

```env
VIRUSTOTAL_API_KEY=
```

---

## RBAC

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_RBAC_ENABLED` | bool | `true` | Enable RBAC features |

---

## Compliance

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_COMPLIANCE_ENABLED` | bool | `true` | Enable compliance features |
| `DPO_EMAIL` | string | - | Data Protection Officer email |

---

## Analytics & Monitoring

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_ANALYTICS_ENABLED` | bool | `true` | Enable analytics |

### Alert Channels

```env
SLACK_SECURITY_WEBHOOK=
```

---

## Logging

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_LOGGING_ENABLED` | bool | `true` | Enable security logging |
| `SECURITY_LOG_CHANNEL` | string | `'security'` | Log channel name |

---

## Environment-Specific Settings

### Development

```env
SECURITY_CSP_REPORT_ONLY=true
SECURITY_HIBP_ENABLED=false
SECURITY_MALWARE_SCANNING_ENABLED=false
```

### Staging

```env
SECURITY_CSP_REPORT_ONLY=true
SECURITY_HIBP_ENABLED=true
SECURITY_MALWARE_SCANNING_ENABLED=false
```

### Production

```env
SECURITY_CSP_REPORT_ONLY=false
SECURITY_HIBP_ENABLED=true
SECURITY_MALWARE_SCANNING_ENABLED=true
SECURITY_MALWARE_DRIVER=clamav

SESSION_DRIVER=database
SESSION_SECURE_COOKIE=true
SESSION_SAME_SITE=strict
```

---

## Complete Example

Here's a complete `.env.example` for the security package:

```env
# =============================================================================
# ArtisanPack Security Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# Core Settings
# -----------------------------------------------------------------------------
SECURITY_ENABLED=true

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------
SECURITY_AUTH_ENABLED=true
SECURITY_DEVICE_FINGERPRINTING_ENABLED=true

# Social Authentication
SECURITY_SOCIAL_AUTH_ENABLED=false
SECURITY_SOCIAL_GOOGLE_ENABLED=false
SECURITY_SOCIAL_MICROSOFT_ENABLED=false
SECURITY_SOCIAL_GITHUB_ENABLED=false
SECURITY_SOCIAL_FACEBOOK_ENABLED=false
SECURITY_SOCIAL_APPLE_ENABLED=false
SECURITY_SOCIAL_LINKEDIN_ENABLED=false

# Google OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Microsoft OAuth
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_TENANT=common

# GitHub OAuth
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Facebook OAuth
FACEBOOK_CLIENT_ID=
FACEBOOK_CLIENT_SECRET=

# Apple OAuth
APPLE_CLIENT_ID=
APPLE_CLIENT_SECRET=
APPLE_TEAM_ID=
APPLE_KEY_ID=

# LinkedIn OAuth
LINKEDIN_CLIENT_ID=
LINKEDIN_CLIENT_SECRET=

# SSO
SECURITY_SSO_ENABLED=false
SECURITY_SAML_ENABLED=false
SECURITY_OIDC_ENABLED=false
SECURITY_LDAP_ENABLED=false

# SAML
SAML_IDP_ENTITY_ID=
SAML_IDP_SSO_URL=
SAML_IDP_SLO_URL=
SAML_IDP_CERTIFICATE=
SAML_SP_ENTITY_ID=
SAML_SP_ACS_URL=
SAML_SP_SLS_URL=
SAML_SP_CERTIFICATE=
SAML_SP_PRIVATE_KEY=

# OIDC
OIDC_ISSUER=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
OIDC_REDIRECT_URI=

# LDAP
LDAP_HOST=ldap.example.com
LDAP_PORT=389
LDAP_BASE_DN=
LDAP_USERNAME=
LDAP_PASSWORD=
LDAP_SSL=false
LDAP_TLS=true

# WebAuthn
SECURITY_WEBAUTHN_ENABLED=false
WEBAUTHN_RP_ID=

# Biometric
SECURITY_BIOMETRIC_ENABLED=false

# -----------------------------------------------------------------------------
# Two-Factor Authentication
# -----------------------------------------------------------------------------
SECURITY_2FA_ENABLED=true

# Twilio (SMS 2FA)
TWILIO_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM=

# -----------------------------------------------------------------------------
# Password Security
# -----------------------------------------------------------------------------
SECURITY_PASSWORD_ENABLED=true
SECURITY_HIBP_ENABLED=true

# -----------------------------------------------------------------------------
# API Security
# -----------------------------------------------------------------------------
SECURITY_API_ENABLED=true
SECURITY_API_TOKEN_EXPIRATION=365

# -----------------------------------------------------------------------------
# Session Security
# -----------------------------------------------------------------------------
SECURITY_ADVANCED_SESSIONS_ENABLED=true
SECURITY_STEP_UP_ENABLED=true

# -----------------------------------------------------------------------------
# Content Security Policy
# -----------------------------------------------------------------------------
SECURITY_CSP_ENABLED=true
SECURITY_CSP_REPORT_ONLY=false
CSP_PROFILE=production

# -----------------------------------------------------------------------------
# Security Headers
# -----------------------------------------------------------------------------
SECURITY_HEADERS_ENABLED=true

# -----------------------------------------------------------------------------
# File Upload Security
# -----------------------------------------------------------------------------
SECURITY_FILE_UPLOAD_ENABLED=true
SECURITY_MALWARE_SCANNING_ENABLED=false
SECURITY_MALWARE_DRIVER=null
VIRUSTOTAL_API_KEY=

# -----------------------------------------------------------------------------
# RBAC
# -----------------------------------------------------------------------------
SECURITY_RBAC_ENABLED=true

# -----------------------------------------------------------------------------
# Compliance
# -----------------------------------------------------------------------------
SECURITY_COMPLIANCE_ENABLED=true
DPO_EMAIL=

# -----------------------------------------------------------------------------
# Analytics & Monitoring
# -----------------------------------------------------------------------------
SECURITY_ANALYTICS_ENABLED=true
SLACK_SECURITY_WEBHOOK=

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
SECURITY_LOGGING_ENABLED=true
SECURITY_LOG_CHANNEL=security
```

---

## Related Documentation

- [Configuration Reference](configuration-reference.md)
- [Implementation Guide](implementation-guide.md)
- [Troubleshooting Guide](troubleshooting.md)
