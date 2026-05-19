---
title: Command Reference
---

# Command Reference

Complete reference for all Artisan commands provided by the ArtisanPack Security package.

## Command Categories

- [Security Audit & Analysis](#security-audit--analysis)
- [User Management](#user-management)
- [Role & Permission Management](#role--permission-management)
- [Two-Factor Authentication](#two-factor-authentication)
- [API Token Management](#api-token-management)
- [Session Management](#session-management)
- [Password Management](#password-management)
- [File Security](#file-security)
- [CSP Management](#csp-management)
- [Compliance](#compliance)
- [Maintenance & Cleanup](#maintenance--cleanup)

---

## Security Audit & Analysis

### security:audit

Run a comprehensive security audit of your application.

```bash
php artisan security:audit [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--check=<type>` | Run specific check (headers, authentication, authorization, config) |
| `--format=<format>` | Output format (text, json, junit, html) |
| `--output=<file>` | Save report to file |
| `--email=<address>` | Email report to address |
| `--silent` | Suppress console output |
| `--fail-on-warning` | Exit with error on warnings |

**Examples:**

```bash
# Full security audit
php artisan security:audit

# Specific checks only
php artisan security:audit --check=headers --check=authentication

# Generate HTML report
php artisan security:audit --format=html --output=security-report.html

# CI/CD integration (JUnit format)
php artisan security:audit --format=junit --output=results.xml --fail-on-warning
```

---

### security:check-config

Verify security configuration is properly set.

```bash
php artisan security:check-config [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--fix` | Attempt to fix issues automatically |
| `--env=<environment>` | Check for specific environment |

**Examples:**

```bash
# Check configuration
php artisan security:check-config

# Check for production environment
php artisan security:check-config --env=production

# Auto-fix issues
php artisan security:check-config --fix
```

---

### security:check-session

Verify session security configuration.

```bash
php artisan security:check-session
```

Checks:
- Session encryption status
- Session driver security
- Cookie settings (secure, httpOnly, sameSite)

---

### security:test-headers

Test security headers on a URL.

```bash
php artisan security:test-headers [url] [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `url` | URL to test (default: APP_URL) |

**Options:**

| Option | Description |
|--------|-------------|
| `--grade` | Show security grade |
| `--verbose` | Show detailed header analysis |
| `--insecure` | Skip SSL verification |

**Examples:**

```bash
# Test application headers
php artisan security:test-headers

# Test specific URL
php artisan security:test-headers https://example.com

# Show detailed analysis
php artisan security:test-headers --verbose --grade
```

---

### security:scan-dependencies

Scan for known vulnerable dependencies.

```bash
php artisan security:scan-dependencies [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--format=<format>` | Output format (text, json) |
| `--fail-on-vulnerability` | Exit with error if vulnerabilities found |

---

### security:check-user

Check security status for a specific user.

```bash
php artisan security:check-user <user> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `user` | User ID or email |

**Options:**

| Option | Description |
|--------|-------------|
| `--severity=<level>` | Filter by severity (low, medium, high, critical) |

**Examples:**

```bash
# Check user by ID
php artisan security:check-user 1

# Check user by email
php artisan security:check-user admin@example.com

# Show only high severity issues
php artisan security:check-user 1 --severity=high
```

---

## User Management

### user:create

Create a new user account.

```bash
php artisan user:create [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--name=<name>` | User's name |
| `--email=<email>` | User's email |
| `--password=<password>` | User's password |
| `--role=<role>` | Assign role(s) |
| `--verify-email` | Mark email as verified |

**Examples:**

```bash
# Interactive creation
php artisan user:create

# With options
php artisan user:create --name="John Doe" --email="john@example.com" --role=admin
```

---

### user:assign-role

Assign a role to a user.

```bash
php artisan user:assign-role <user> <role>
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `user` | User ID or email |
| `role` | Role name to assign |

**Examples:**

```bash
php artisan user:assign-role 1 admin
php artisan user:assign-role user@example.com editor
```

---

### user:remove-role

Remove a role from a user.

```bash
php artisan user:remove-role <user> <role>
```

---

### user:lock

Lock a user account.

```bash
php artisan user:lock <user> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--reason=<reason>` | Reason for locking |
| `--duration=<minutes>` | Lock duration (0 = permanent) |
| `--notify` | Notify user via email |

---

### user:unlock

Unlock a user account.

```bash
php artisan user:unlock <user> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--notify` | Notify user via email |

---

## Role & Permission Management

### role:create

Create a new role.

```bash
php artisan role:create <name> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `name` | Role name (slug) |

**Options:**

| Option | Description |
|--------|-------------|
| `--display-name=<name>` | Human-readable name |
| `--description=<desc>` | Role description |
| `--permissions=<perms>` | Comma-separated permissions |

**Examples:**

```bash
php artisan role:create editor --display-name="Content Editor"
php artisan role:create moderator --permissions=edit-posts,delete-comments
```

---

### role:delete

Delete a role.

```bash
php artisan role:delete <name> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--force` | Delete even if users have this role |

---

### role:list

List all roles.

```bash
php artisan role:list [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--with-permissions` | Show permissions for each role |
| `--with-users` | Show user count for each role |

---

### permission:create

Create a new permission.

```bash
php artisan permission:create <name> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `name` | Permission name (slug) |

**Options:**

| Option | Description |
|--------|-------------|
| `--display-name=<name>` | Human-readable name |
| `--description=<desc>` | Permission description |
| `--group=<group>` | Permission group |

---

### permission:delete

Delete a permission.

```bash
php artisan permission:delete <name>
```

---

### permission:list

List all permissions.

```bash
php artisan permission:list [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--group=<group>` | Filter by group |

---

### role:assign-permission

Assign a permission to a role.

```bash
php artisan role:assign-permission <role> <permission>
```

---

### role:remove-permission

Remove a permission from a role.

```bash
php artisan role:remove-permission <role> <permission>
```

---

## Two-Factor Authentication

### 2fa:enable

Enable 2FA for a user.

```bash
php artisan 2fa:enable <user> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `user` | User ID or email |

**Options:**

| Option | Description |
|--------|-------------|
| `--show-qr` | Display QR code in terminal |
| `--notify` | Send setup email to user |

---

### 2fa:disable

Disable 2FA for a user.

```bash
php artisan 2fa:disable <user> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--force` | Disable without confirmation |

---

### 2fa:status

Check 2FA status for a user.

```bash
php artisan 2fa:status <user>
```

---

### 2fa:regenerate-recovery

Regenerate recovery codes for a user.

```bash
php artisan 2fa:regenerate-recovery <user> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--show` | Display new codes |
| `--email` | Email codes to user |

---

### 2fa:report

Generate 2FA adoption report.

```bash
php artisan 2fa:report [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--format=<format>` | Output format (text, json, csv) |

---

## API Token Management

### token:create

Create an API token for a user.

```bash
php artisan token:create <user> <name> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `user` | User ID or email |
| `name` | Token name |

**Options:**

| Option | Description |
|--------|-------------|
| `--abilities=<list>` | Comma-separated abilities |
| `--expires=<days>` | Expiration in days |

**Examples:**

```bash
php artisan token:create 1 "API Access" --abilities=read,write
php artisan token:create admin@example.com "Service Token" --expires=30
```

---

### token:revoke

Revoke an API token.

```bash
php artisan token:revoke <token-id>
```

---

### token:list

List API tokens for a user.

```bash
php artisan token:list <user> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--all` | Include revoked tokens |

---

### token:cleanup

Remove expired tokens.

```bash
php artisan token:cleanup [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview without deleting |

---

### api:security:check

Check API security configuration and settings.

```bash
php artisan api:security:check [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--fix` | Attempt to fix issues automatically |
| `--verbose` | Show detailed output |

**Examples:**

```bash
# Check API security settings
php artisan api:security:check

# Check with detailed output
php artisan api:security:check --verbose

# Check and fix issues
php artisan api:security:check --fix
```

---

## Session Management

### session:terminate

Terminate sessions for a user.

```bash
php artisan session:terminate <user> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `user` | User ID or email |

**Options:**

| Option | Description |
|--------|-------------|
| `--except-current` | Keep current session |
| `--all` | Terminate all sessions (all users) |

---

### session:list

List active sessions for a user.

```bash
php artisan session:list <user>
```

---

### session:cleanup

Clean up expired sessions.

```bash
php artisan session:cleanup [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview without deleting |

---

## Password Management

### password:expire

Expire password for a user (force reset).

```bash
php artisan password:expire <user> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--notify` | Send email notification |

---

### password:expire-all

Expire passwords for all users.

```bash
php artisan password:expire-all [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--role=<role>` | Only users with role |
| `--notify` | Send email notifications |

---

### password:check-breached

Check if a password has been breached.

```bash
php artisan password:check-breached
```

Prompts for password input securely.

---

## File Security

### security:cleanup-files

Clean up expired/temporary files.

```bash
php artisan security:cleanup-files [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--days=<days>` | Files older than N days (default: 30) |
| `--only-infected` | Clean only infected files |
| `--dry-run` | Preview without deleting |

**Examples:**

```bash
# Clean files older than 30 days
php artisan security:cleanup-files --days=30

# Preview cleanup
php artisan security:cleanup-files --dry-run

# Clean only infected files
php artisan security:cleanup-files --only-infected
```

---

### security:scan-quarantine

Scan quarantined files for malware.

```bash
php artisan security:scan-quarantine [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--limit=<count>` | Maximum files to scan (default: 100) |
| `--delete-infected` | Automatically delete infected files |

**Examples:**

```bash
# Scan quarantined files
php artisan security:scan-quarantine

# Scan with custom limit
php artisan security:scan-quarantine --limit=50

# Scan and delete infected files
php artisan security:scan-quarantine --delete-infected
```

---

## CSP Management

### security:generate-csp

Generate a CSP policy interactively.

```bash
php artisan security:generate-csp [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--template=<name>` | Use template (strict, relaxed) |
| `--preset=<presets>` | Add presets (google-analytics, stripe) |
| `--output=<file>` | Save to file |

---

### security:csp:test

Test CSP policy configuration.

```bash
php artisan security:csp:test [url] [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `url` | URL to test (default: APP_URL) |

**Options:**

| Option | Description |
|--------|-------------|
| `--validate` | Validate policy syntax |
| `--audit` | Check for common issues |

**Examples:**

```bash
# Test CSP on application URL
php artisan security:csp:test

# Test specific URL
php artisan security:csp:test https://example.com

# Validate and audit
php artisan security:csp:test --validate --audit
```

---

### csp:violations

Manage CSP violations.

```bash
php artisan csp:violations [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--summary` | Show violation summary |
| `--export=<file>` | Export to file |
| `--clear` | Clear old violations |
| `--older-than=<days>` | For --clear, specify age |

---

### csp:analyze

Analyze CSP violations and suggest improvements.

```bash
php artisan csp:analyze
```

---

## Compliance

### compliance:cleanup

Run data retention cleanup.

```bash
php artisan compliance:cleanup [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--type=<type>` | Clean specific data type |
| `--dry-run` | Preview without deleting |
| `--force` | Ignore schedule |

---

### compliance:report

Generate compliance reports.

```bash
php artisan compliance:report <type> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `type` | Report type (gdpr, consent, audit, retention) |

**Options:**

| Option | Description |
|--------|-------------|
| `--period=<period>` | Time period (7d, 30d, 90d) |
| `--from=<date>` | Start date |
| `--to=<date>` | End date |
| `--format=<format>` | Output format (text, json, pdf, csv) |
| `--output=<file>` | Save to file |
| `--email=<address>` | Email report |

---

### compliance:export-user

Export user data (GDPR data portability).

```bash
php artisan compliance:export-user <user> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--output=<dir>` | Output directory |
| `--format=<format>` | Format (json, csv, zip) |

---

### compliance:process-erasures

Process pending account deletion requests.

```bash
php artisan compliance:process-erasures
```

---

### compliance:status

Check overall compliance status.

```bash
php artisan compliance:status
```

---

### compliance:processing-activities

List data processing activities.

```bash
php artisan compliance:processing-activities
```

---

## Maintenance & Cleanup

### security:clear-cache

Clear security-related caches.

```bash
php artisan security:clear-cache [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--roles` | Clear role/permission cache |
| `--sessions` | Clear session cache |
| `--all` | Clear all security caches |

---

### security:metrics

View security metrics.

```bash
php artisan security:metrics [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--period=<period>` | Time period |
| `--type=<type>` | Metric type |

---

### security:metrics-cleanup

Clean up old metrics data.

```bash
php artisan security:metrics-cleanup [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--days=<days>` | Delete data older than N days |
| `--dry-run` | Preview without deleting |

---

### security:threats

View current threat status.

```bash
php artisan security:threats [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--active` | Show only active threats |

---

### security:alerts

Manage security alerts.

```bash
php artisan security:alerts [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--unacknowledged` | Show only unacknowledged |
| `--acknowledge=<id>` | Acknowledge an alert |

---

### security:test-alerts

Test alert channels.

```bash
php artisan security:test-alerts [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--channel=<channel>` | Test specific channel |

---

### security:report

Generate security reports.

```bash
php artisan security:report <type> [options]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `type` | Report type (summary, authentication, threats, api) |

**Options:**

| Option | Description |
|--------|-------------|
| `--period=<period>` | Time period |
| `--format=<format>` | Output format |
| `--email=<address>` | Email report |

---

## Related Documentation

- [Configuration Reference](configuration-reference.md)
- [Implementation Guide](implementation-guide.md)
- [Troubleshooting Guide](troubleshooting.md)
