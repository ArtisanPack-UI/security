# Security Analytics & Monitoring Implementation Plan

## Overview

This document outlines the implementation plan for advanced security analytics and real-time monitoring capabilities in the ArtisanPack Security package. The goal is to provide comprehensive visibility into security events, detect anomalies, and enable automated responses to threats.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Security Metrics Collection](#security-metrics-collection)
3. [Real-time Security Event Dashboard](#real-time-security-event-dashboard)
4. [Anomaly Detection Algorithms](#anomaly-detection-algorithms)
5. [Threat Intelligence Integration](#threat-intelligence-integration)
6. [Automated Incident Response](#automated-incident-response)
7. [Security Reporting and Alerting](#security-reporting-and-alerting)
8. [SIEM Integration](#siem-integration)
9. [Database Schema](#database-schema)
10. [Configuration](#configuration)
11. [File Structure](#file-structure)
12. [Implementation Order](#implementation-order)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Laravel Application                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │   Events    │  │ Middleware  │  │  Services   │                │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                │
│         │                │                │                        │
│         └────────────────┼────────────────┘                        │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │              Security Analytics Pipeline                     │  │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐ │  │
│  │  │ Collector │→ │ Processor │→ │ Analyzer  │→ │ Responder│ │  │
│  │  └───────────┘  └───────────┘  └───────────┘  └──────────┘ │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                          │                                          │
│         ┌────────────────┼────────────────┐                        │
│         ▼                ▼                ▼                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │  Database   │  │    Cache    │  │    Queue    │                │
│  └─────────────┘  └─────────────┘  └─────────────┘                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    External Integrations                            │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐   │
│  │   SIEM    │  │  Threat   │  │  Alerting │  │   Dashboard   │   │
│  │  Systems  │  │   Intel   │  │  Services │  │   (Frontend)  │   │
│  └───────────┘  └───────────┘  └───────────┘  └───────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Core Components

1. **Metrics Collector** - Gathers security events from various sources
2. **Event Processor** - Normalizes and enriches security data
3. **Anomaly Analyzer** - Detects unusual patterns and threats
4. **Incident Responder** - Triggers automated responses
5. **Dashboard API** - Serves real-time data to frontend
6. **SIEM Exporter** - Sends data to external systems

---

## Security Metrics Collection

### Metrics to Collect

#### Authentication Metrics
- Login attempts (successful/failed)
- Login locations and devices
- Session creation/destruction
- Password changes/resets
- MFA usage and failures
- Account lockouts

#### Authorization Metrics
- Permission checks (granted/denied)
- Role changes
- Privilege escalation attempts
- Resource access patterns

#### API Security Metrics
- API request rates per token/user
- API errors and failures
- Token usage patterns
- Rate limit hits

#### Application Security Metrics
- CSP violations
- Input validation failures
- File upload attempts
- Suspicious request patterns

### Implementation

#### MetricsCollector Service

```php
namespace ArtisanPackUI\Security\Analytics;

class MetricsCollector
{
    // Collect a security metric
    public function collect(string $category, string $metric, array $data = [], array $tags = []): void;

    // Increment a counter metric
    public function increment(string $metric, int $value = 1, array $tags = []): void;

    // Record a gauge metric (point-in-time value)
    public function gauge(string $metric, float $value, array $tags = []): void;

    // Record a timing metric
    public function timing(string $metric, float $milliseconds, array $tags = []): void;

    // Record a histogram metric
    public function histogram(string $metric, float $value, array $tags = []): void;

    // Flush collected metrics to storage
    public function flush(): void;
}
```

#### SecurityMetric Model

```php
namespace ArtisanPackUI\Security\Models;

class SecurityMetric extends Model
{
    protected $fillable = [
        'category',      // authentication, authorization, api, application
        'metric_name',   // login_attempt, permission_denied, etc.
        'metric_type',   // counter, gauge, timing, histogram
        'value',
        'tags',          // JSON: user_id, ip, endpoint, etc.
        'recorded_at',
    ];
}
```

#### Event Listeners for Automatic Collection

Create listeners that automatically collect metrics from existing events:
- `AuthenticationAttemptListener`
- `AuthorizationCheckListener`
- `ApiRequestListener`
- `SecurityViolationListener`

---

## Real-time Security Event Dashboard

### Dashboard Features

1. **Live Event Feed** - Real-time stream of security events
2. **Threat Level Indicator** - Current security posture
3. **Geographic Map** - Login/attack origins
4. **Time-series Charts** - Event trends over time
5. **Top Threats Widget** - Most common attack vectors
6. **Active Sessions Monitor** - Current user sessions
7. **Anomaly Alerts Panel** - Detected anomalies

### API Endpoints

```
GET  /api/security/dashboard/summary
GET  /api/security/dashboard/events/live
GET  /api/security/dashboard/metrics/{metric}
GET  /api/security/dashboard/threats/current
GET  /api/security/dashboard/geographic
GET  /api/security/dashboard/timeline
POST /api/security/dashboard/acknowledge/{alertId}
```

### Implementation

#### DashboardController

```php
namespace ArtisanPackUI\Security\Http\Controllers;

class SecurityDashboardController extends Controller
{
    // Get dashboard summary (counts, threat level, etc.)
    public function summary(): JsonResponse;

    // Get live events stream (supports Server-Sent Events)
    public function liveEvents(Request $request): StreamedResponse;

    // Get specific metric data
    public function metric(string $metric, Request $request): JsonResponse;

    // Get current threat assessment
    public function threats(): JsonResponse;

    // Get geographic distribution of events
    public function geographic(): JsonResponse;

    // Get timeline data for charts
    public function timeline(Request $request): JsonResponse;
}
```

#### DashboardService

```php
namespace ArtisanPackUI\Security\Analytics;

class DashboardService
{
    // Calculate overall threat level (0-100)
    public function calculateThreatLevel(): int;

    // Get aggregated summary stats
    public function getSummary(Carbon $from, Carbon $to): array;

    // Get real-time event stream
    public function getEventStream(): Generator;

    // Get metric time series
    public function getMetricTimeSeries(string $metric, string $interval, Carbon $from, Carbon $to): array;

    // Get top N items for a dimension
    public function getTopN(string $dimension, int $limit = 10): Collection;
}
```

### Real-time Updates

Use Laravel Broadcasting with Redis/Pusher for real-time updates:

```php
// Event for broadcasting security events to dashboard
class SecurityEventOccurred implements ShouldBroadcast
{
    public function broadcastOn(): array
    {
        return [new PrivateChannel('security.dashboard')];
    }
}
```

---

## Anomaly Detection Algorithms

### Detection Categories

#### 1. Statistical Anomaly Detection
- **Z-Score Analysis** - Detect values outside normal distribution
- **Moving Average** - Identify deviations from rolling averages
- **Seasonal Decomposition** - Account for time-based patterns

#### 2. Behavioral Analysis
- **User Behavior Profiling** - Learn normal user patterns
- **Session Fingerprinting** - Detect session hijacking
- **Access Pattern Analysis** - Identify unusual resource access

#### 3. Rule-Based Detection
- **Threshold Violations** - Configurable alert thresholds
- **Pattern Matching** - Known attack signatures
- **Velocity Checks** - Rate of change detection

#### 4. Machine Learning (Optional/Future)
- **Isolation Forest** - Unsupervised anomaly detection
- **LSTM Networks** - Sequence-based anomaly detection

### Implementation

#### AnomalyDetector Service

```php
namespace ArtisanPackUI\Security\Analytics\Anomaly;

class AnomalyDetector
{
    // Run all enabled detectors
    public function analyze(SecurityEvent $event): AnomalyResult;

    // Register a custom detector
    public function registerDetector(string $name, AnomalyDetectorInterface $detector): void;

    // Get all detected anomalies for a time range
    public function getAnomalies(Carbon $from, Carbon $to): Collection;

    // Update baseline profiles
    public function updateBaselines(): void;
}
```

#### Detector Interface

```php
namespace ArtisanPackUI\Security\Analytics\Contracts;

interface AnomalyDetectorInterface
{
    // Analyze an event for anomalies
    public function detect(SecurityEvent $event, array $context = []): ?Anomaly;

    // Get detector name
    public function getName(): string;

    // Get detector category
    public function getCategory(): string;

    // Check if detector is enabled
    public function isEnabled(): bool;
}
```

#### Built-in Detectors

```php
// Statistical Detectors
ZScoreDetector::class           // Detects statistical outliers
MovingAverageDetector::class    // Detects trend deviations
ThresholdDetector::class        // Detects threshold violations

// Behavioral Detectors
UserBehaviorDetector::class     // Detects unusual user behavior
GeoVelocityDetector::class      // Detects impossible travel
SessionAnomalyDetector::class   // Detects session anomalies
AccessPatternDetector::class    // Detects unusual access patterns

// Rule-Based Detectors
BruteForceDetector::class       // Detects brute force attempts
CredentialStuffingDetector::class // Detects credential stuffing
PrivilegeEscalationDetector::class // Detects privilege escalation attempts
```

#### Anomaly Model

```php
namespace ArtisanPackUI\Security\Models;

class Anomaly extends Model
{
    protected $fillable = [
        'detector',       // Which detector found this
        'category',       // statistical, behavioral, rule_based
        'severity',       // info, low, medium, high, critical
        'score',          // 0-100 confidence score
        'description',
        'event_id',       // Related security event
        'user_id',
        'ip_address',
        'metadata',       // JSON with detector-specific data
        'resolved_at',
        'resolved_by',
        'resolution_notes',
    ];
}
```

#### User Behavior Profile

```php
namespace ArtisanPackUI\Security\Models;

class UserBehaviorProfile extends Model
{
    protected $fillable = [
        'user_id',
        'profile_type',        // login, api_usage, resource_access
        'baseline_data',       // JSON with statistical baselines
        'last_updated_at',
        'sample_count',
        'confidence_score',
    ];
}
```

---

## Threat Intelligence Integration

### Supported Threat Intelligence Sources

1. **IP Reputation Services**
   - AbuseIPDB
   - VirusTotal
   - IPQualityScore
   - Custom IP blocklists

2. **Domain/URL Intelligence**
   - Google Safe Browsing
   - URLhaus
   - PhishTank

3. **File Hash Intelligence**
   - VirusTotal
   - MalwareBazaar

4. **Custom Threat Feeds**
   - STIX/TAXII feeds
   - Custom CSV/JSON feeds
   - Internal threat lists

### Implementation

#### ThreatIntelligenceService

```php
namespace ArtisanPackUI\Security\Analytics\ThreatIntel;

class ThreatIntelligenceService
{
    // Check IP against threat intelligence
    public function checkIp(string $ip): ThreatAssessment;

    // Check domain/URL against threat intelligence
    public function checkUrl(string $url): ThreatAssessment;

    // Check file hash against threat intelligence
    public function checkFileHash(string $hash, string $algorithm = 'sha256'): ThreatAssessment;

    // Sync threat feeds
    public function syncFeeds(): void;

    // Add indicator to local blocklist
    public function addIndicator(string $type, string $value, array $metadata = []): void;

    // Check if indicator is in local blocklist
    public function isBlocked(string $type, string $value): bool;
}
```

#### Provider Interface

```php
namespace ArtisanPackUI\Security\Analytics\Contracts;

interface ThreatIntelProviderInterface
{
    public function getName(): string;
    public function getType(): string; // ip, domain, hash
    public function check(string $indicator): ?ThreatReport;
    public function isAvailable(): bool;
}
```

#### Built-in Providers

```php
// IP Reputation
AbuseIpDbProvider::class
IpQualityScoreProvider::class
VirusTotalIpProvider::class

// URL/Domain
GoogleSafeBrowsingProvider::class
UrlHausProvider::class

// File Hash
VirusTotalHashProvider::class
MalwareBazaarProvider::class

// Custom Feeds
StixTaxiiProvider::class
CustomFeedProvider::class
```

#### ThreatIndicator Model

```php
namespace ArtisanPackUI\Security\Models;

class ThreatIndicator extends Model
{
    protected $fillable = [
        'type',           // ip, domain, url, hash, email
        'value',
        'source',         // Provider name or 'internal'
        'threat_type',    // malware, phishing, spam, bruteforce, etc.
        'severity',
        'confidence',     // 0-100
        'first_seen_at',
        'last_seen_at',
        'expires_at',
        'metadata',
    ];
}
```

---

## Automated Incident Response

### Response Actions

1. **User Actions**
   - Lock account
   - Force password reset
   - Revoke all sessions
   - Require MFA verification
   - Send notification

2. **IP Actions**
   - Block IP temporarily
   - Block IP permanently
   - Add to watchlist
   - Rate limit

3. **Session Actions**
   - Terminate session
   - Require re-authentication
   - Downgrade session privileges

4. **System Actions**
   - Enable enhanced logging
   - Trigger security scan
   - Create incident ticket
   - Notify security team

### Implementation

#### IncidentResponder Service

```php
namespace ArtisanPackUI\Security\Analytics\Response;

class IncidentResponder
{
    // Process an anomaly and trigger appropriate response
    public function respond(Anomaly $anomaly): IncidentResponse;

    // Execute a specific response action
    public function executeAction(string $action, array $parameters): ActionResult;

    // Get response playbook for anomaly type
    public function getPlaybook(string $anomalyType): ResponsePlaybook;

    // Register custom response action
    public function registerAction(string $name, ResponseActionInterface $action): void;
}
```

#### ResponsePlaybook Model

```php
namespace ArtisanPackUI\Security\Models;

class ResponsePlaybook extends Model
{
    protected $fillable = [
        'name',
        'description',
        'trigger_conditions',  // JSON: conditions that trigger this playbook
        'actions',             // JSON: ordered list of actions to take
        'is_active',
        'requires_approval',   // Whether human approval is needed
        'cooldown_minutes',    // Minimum time between executions
    ];
}
```

#### Action Interface

```php
namespace ArtisanPackUI\Security\Analytics\Contracts;

interface ResponseActionInterface
{
    public function getName(): string;
    public function getDescription(): string;
    public function execute(array $parameters): ActionResult;
    public function canUndo(): bool;
    public function undo(array $parameters): ActionResult;
    public function validate(array $parameters): array; // Returns validation errors
}
```

#### Built-in Response Actions

```php
// User Actions
LockAccountAction::class
ForcePasswordResetAction::class
RevokeSessionsAction::class
RequireMfaAction::class
SendNotificationAction::class

// IP Actions
BlockIpAction::class
RateLimitIpAction::class
WatchlistIpAction::class

// Session Actions
TerminateSessionAction::class
RequireReauthAction::class
DowngradePrivilegesAction::class

// System Actions
EnableEnhancedLoggingAction::class
CreateIncidentTicketAction::class
NotifySecurityTeamAction::class
TriggerSecurityScanAction::class
```

#### Incident Model

```php
namespace ArtisanPackUI\Security\Models;

class SecurityIncident extends Model
{
    protected $fillable = [
        'incident_number',     // Auto-generated: INC-2024-000001
        'title',
        'description',
        'severity',            // info, low, medium, high, critical
        'status',              // open, investigating, contained, resolved, closed
        'category',
        'source_anomaly_id',
        'affected_users',      // JSON array of user IDs
        'affected_ips',        // JSON array of IPs
        'actions_taken',       // JSON array of actions executed
        'assigned_to',
        'opened_at',
        'contained_at',
        'resolved_at',
        'closed_at',
        'root_cause',
        'lessons_learned',
    ];
}
```

---

## Security Reporting and Alerting

### Report Types

1. **Executive Summary** - High-level security posture
2. **Threat Report** - Detailed threat analysis
3. **Compliance Report** - Regulatory compliance status
4. **Incident Report** - Incident details and timeline
5. **User Activity Report** - User behavior analysis
6. **Trend Report** - Security trends over time

### Alert Channels

- Email
- Slack
- Microsoft Teams
- PagerDuty
- OpsGenie
- Webhooks
- SMS (via Twilio/Vonage)

### Implementation

#### ReportGenerator Service

```php
namespace ArtisanPackUI\Security\Analytics\Reporting;

class ReportGenerator
{
    // Generate a report
    public function generate(string $type, array $options = []): SecurityReport;

    // Schedule recurring report
    public function schedule(string $type, string $cron, array $recipients, array $options = []): ScheduledReport;

    // Export report to format
    public function export(SecurityReport $report, string $format): string; // pdf, html, csv, json

    // Send report to recipients
    public function send(SecurityReport $report, array $recipients): void;
}
```

#### AlertManager Service

```php
namespace ArtisanPackUI\Security\Analytics\Alerting;

class AlertManager
{
    // Send an alert
    public function alert(SecurityAlert $alert): void;

    // Register alert channel
    public function registerChannel(string $name, AlertChannelInterface $channel): void;

    // Get alert routing for severity/category
    public function getRouting(string $severity, string $category): array;

    // Check if alert should be suppressed (deduplication)
    public function shouldSuppress(SecurityAlert $alert): bool;
}
```

#### Alert Channel Interface

```php
namespace ArtisanPackUI\Security\Analytics\Contracts;

interface AlertChannelInterface
{
    public function getName(): string;
    public function send(SecurityAlert $alert, array $config): bool;
    public function isAvailable(): bool;
    public function getRequiredConfig(): array;
}
```

#### Built-in Channels

```php
EmailAlertChannel::class
SlackAlertChannel::class
TeamsAlertChannel::class
PagerDutyAlertChannel::class
OpsGenieAlertChannel::class
WebhookAlertChannel::class
SmsAlertChannel::class
DatabaseAlertChannel::class  // Store alerts in DB for dashboard
```

#### Alert Rule Model

```php
namespace ArtisanPackUI\Security\Models;

class AlertRule extends Model
{
    protected $fillable = [
        'name',
        'description',
        'conditions',          // JSON: conditions that trigger alert
        'severity',
        'channels',            // JSON: channels to send to
        'recipients',          // JSON: per-channel recipients
        'is_active',
        'cooldown_minutes',
        'escalation_policy',   // JSON: escalation rules
    ];
}
```

---

## SIEM Integration

### Supported SIEM Systems

1. **Splunk** - HTTP Event Collector (HEC)
2. **Elastic Security** - Elasticsearch ingest
3. **Microsoft Sentinel** - Log Analytics API
4. **IBM QRadar** - Syslog/REST API
5. **Sumo Logic** - HTTP Source
6. **Datadog** - Log Management API
7. **Generic Syslog** - RFC 5424 format
8. **Generic Webhook** - Custom HTTP endpoint

### Log Formats

- **CEF** (Common Event Format)
- **LEEF** (Log Event Extended Format)
- **JSON** (Structured JSON)
- **Syslog** (RFC 5424)

### Implementation

#### SiemExporter Service

```php
namespace ArtisanPackUI\Security\Analytics\Siem;

class SiemExporter
{
    // Export event to configured SIEM
    public function export(SecurityEvent $event): void;

    // Batch export events
    public function exportBatch(Collection $events): void;

    // Register SIEM provider
    public function registerProvider(string $name, SiemProviderInterface $provider): void;

    // Test SIEM connection
    public function testConnection(string $provider): ConnectionTestResult;

    // Get export statistics
    public function getStats(): array;
}
```

#### SIEM Provider Interface

```php
namespace ArtisanPackUI\Security\Analytics\Contracts;

interface SiemProviderInterface
{
    public function getName(): string;
    public function send(array $events): bool;
    public function formatEvent(SecurityEvent $event): array;
    public function testConnection(): bool;
    public function getRequiredConfig(): array;
}
```

#### Built-in Providers

```php
SplunkHecProvider::class
ElasticsearchProvider::class
MicrosoftSentinelProvider::class
QRadarProvider::class
SumoLogicProvider::class
DatadogProvider::class
SyslogProvider::class
WebhookProvider::class
```

#### Event Formatter

```php
namespace ArtisanPackUI\Security\Analytics\Siem;

class EventFormatter
{
    // Format event as CEF
    public function toCef(SecurityEvent $event): string;

    // Format event as LEEF
    public function toLeef(SecurityEvent $event): string;

    // Format event as structured JSON
    public function toJson(SecurityEvent $event): array;

    // Format event as Syslog
    public function toSyslog(SecurityEvent $event): string;
}
```

---

## Database Schema

### New Tables

```sql
-- Security metrics storage
CREATE TABLE security_metrics (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    category VARCHAR(50) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_type ENUM('counter', 'gauge', 'timing', 'histogram') NOT NULL,
    value DECIMAL(20, 6) NOT NULL,
    tags JSON,
    recorded_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_category_metric (category, metric_name),
    INDEX idx_recorded_at (recorded_at),
    INDEX idx_category_recorded (category, recorded_at)
);

-- Detected anomalies
CREATE TABLE anomalies (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    detector VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL,
    score TINYINT UNSIGNED NOT NULL,
    description TEXT NOT NULL,
    event_id BIGINT UNSIGNED,
    user_id BIGINT UNSIGNED,
    ip_address VARCHAR(45),
    metadata JSON,
    resolved_at TIMESTAMP NULL,
    resolved_by BIGINT UNSIGNED NULL,
    resolution_notes TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_severity_created (severity, created_at),
    INDEX idx_user (user_id),
    INDEX idx_detector (detector),
    INDEX idx_unresolved (resolved_at, severity)
);

-- User behavior profiles
CREATE TABLE user_behavior_profiles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    profile_type VARCHAR(50) NOT NULL,
    baseline_data JSON NOT NULL,
    sample_count INT UNSIGNED DEFAULT 0,
    confidence_score DECIMAL(5, 2) DEFAULT 0,
    last_updated_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY idx_user_type (user_id, profile_type)
);

-- Threat indicators
CREATE TABLE threat_indicators (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    type ENUM('ip', 'domain', 'url', 'hash', 'email') NOT NULL,
    value VARCHAR(500) NOT NULL,
    source VARCHAR(100) NOT NULL,
    threat_type VARCHAR(50),
    severity ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL,
    confidence TINYINT UNSIGNED NOT NULL,
    first_seen_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY idx_type_value (type, value(255)),
    INDEX idx_expires (expires_at),
    INDEX idx_severity (severity)
);

-- Response playbooks
CREATE TABLE response_playbooks (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    trigger_conditions JSON NOT NULL,
    actions JSON NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    requires_approval BOOLEAN DEFAULT FALSE,
    cooldown_minutes INT UNSIGNED DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Security incidents
CREATE TABLE security_incidents (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    incident_number VARCHAR(20) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('open', 'investigating', 'contained', 'resolved', 'closed') NOT NULL DEFAULT 'open',
    category VARCHAR(50),
    source_anomaly_id BIGINT UNSIGNED,
    affected_users JSON,
    affected_ips JSON,
    actions_taken JSON,
    assigned_to BIGINT UNSIGNED,
    opened_at TIMESTAMP NOT NULL,
    contained_at TIMESTAMP NULL,
    resolved_at TIMESTAMP NULL,
    closed_at TIMESTAMP NULL,
    root_cause TEXT,
    lessons_learned TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status_severity (status, severity),
    INDEX idx_opened (opened_at)
);

-- Alert rules
CREATE TABLE alert_rules (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    conditions JSON NOT NULL,
    severity ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL,
    channels JSON NOT NULL,
    recipients JSON NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    cooldown_minutes INT UNSIGNED DEFAULT 5,
    escalation_policy JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Alert history
CREATE TABLE alert_history (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    rule_id BIGINT UNSIGNED,
    anomaly_id BIGINT UNSIGNED,
    incident_id BIGINT UNSIGNED,
    severity ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL,
    channel VARCHAR(50) NOT NULL,
    recipient VARCHAR(255),
    status ENUM('pending', 'sent', 'failed', 'acknowledged') NOT NULL DEFAULT 'pending',
    message TEXT,
    sent_at TIMESTAMP NULL,
    acknowledged_at TIMESTAMP NULL,
    acknowledged_by BIGINT UNSIGNED,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_rule_created (rule_id, created_at)
);

-- Scheduled reports
CREATE TABLE scheduled_reports (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    report_type VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    recipients JSON NOT NULL,
    options JSON,
    format ENUM('pdf', 'html', 'csv', 'json') DEFAULT 'pdf',
    is_active BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMP NULL,
    next_run_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

---

## Configuration

### config/security.php additions

```php
return [
    // ... existing config ...

    'analytics' => [
        'enabled' => env('SECURITY_ANALYTICS_ENABLED', true),

        'metrics' => [
            'enabled' => true,
            'storage' => 'database', // database, redis, statsd
            'retention_days' => 90,
            'aggregation_interval' => 60, // seconds
        ],

        'anomaly_detection' => [
            'enabled' => true,
            'detectors' => [
                'zscore' => ['enabled' => true, 'threshold' => 3.0],
                'moving_average' => ['enabled' => true, 'window' => 24],
                'threshold' => ['enabled' => true],
                'user_behavior' => ['enabled' => true, 'min_samples' => 10],
                'geo_velocity' => ['enabled' => true, 'max_speed_kmh' => 1000],
                'brute_force' => ['enabled' => true],
                'credential_stuffing' => ['enabled' => true],
            ],
            'baseline_update_interval' => 3600, // seconds
        ],

        'threat_intelligence' => [
            'enabled' => true,
            'cache_ttl' => 3600,
            'providers' => [
                'abuseipdb' => [
                    'enabled' => env('ABUSEIPDB_ENABLED', false),
                    'api_key' => env('ABUSEIPDB_API_KEY'),
                    'threshold' => 25,
                ],
                'virustotal' => [
                    'enabled' => env('VIRUSTOTAL_ENABLED', false),
                    'api_key' => env('VIRUSTOTAL_API_KEY'),
                ],
                // ... more providers
            ],
            'custom_feeds' => [
                // Custom threat feed URLs
            ],
        ],

        'incident_response' => [
            'enabled' => true,
            'auto_respond' => env('SECURITY_AUTO_RESPOND', true),
            'require_approval_for' => ['critical'],
            'default_actions' => [
                'brute_force' => ['block_ip', 'lock_account'],
                'credential_stuffing' => ['lock_account', 'notify_user'],
                // ... more mappings
            ],
        ],

        'alerting' => [
            'enabled' => true,
            'default_channel' => 'email',
            'channels' => [
                'email' => [
                    'enabled' => true,
                    'from' => env('SECURITY_ALERT_FROM', 'security@example.com'),
                ],
                'slack' => [
                    'enabled' => env('SLACK_ALERTS_ENABLED', false),
                    'webhook_url' => env('SLACK_WEBHOOK_URL'),
                    'channel' => '#security-alerts',
                ],
                'pagerduty' => [
                    'enabled' => env('PAGERDUTY_ENABLED', false),
                    'routing_key' => env('PAGERDUTY_ROUTING_KEY'),
                ],
                // ... more channels
            ],
            'routing' => [
                'critical' => ['pagerduty', 'slack', 'email'],
                'high' => ['slack', 'email'],
                'medium' => ['email'],
                'low' => ['database'],
            ],
            'deduplication_window' => 300, // seconds
        ],

        'siem' => [
            'enabled' => env('SIEM_ENABLED', false),
            'provider' => env('SIEM_PROVIDER', 'splunk'),
            'providers' => [
                'splunk' => [
                    'hec_url' => env('SPLUNK_HEC_URL'),
                    'token' => env('SPLUNK_HEC_TOKEN'),
                    'index' => env('SPLUNK_INDEX', 'security'),
                    'source' => env('APP_NAME', 'laravel'),
                ],
                'elasticsearch' => [
                    'hosts' => env('ELASTICSEARCH_HOSTS'),
                    'index' => env('ELASTICSEARCH_INDEX', 'security-events'),
                    'api_key' => env('ELASTICSEARCH_API_KEY'),
                ],
                'syslog' => [
                    'host' => env('SYSLOG_HOST'),
                    'port' => env('SYSLOG_PORT', 514),
                    'protocol' => env('SYSLOG_PROTOCOL', 'udp'),
                    'format' => 'cef', // cef, leef, json
                ],
                // ... more providers
            ],
            'batch_size' => 100,
            'flush_interval' => 10, // seconds
        ],

        'dashboard' => [
            'enabled' => true,
            'refresh_interval' => 30, // seconds
            'event_retention_hours' => 24,
            'require_permission' => 'security.dashboard.view',
        ],

        'reporting' => [
            'enabled' => true,
            'storage_disk' => 'local',
            'storage_path' => 'security-reports',
            'default_format' => 'pdf',
        ],
    ],
];
```

---

## File Structure

```
src/
├── Analytics/
│   ├── Contracts/
│   │   ├── AnomalyDetectorInterface.php
│   │   ├── ThreatIntelProviderInterface.php
│   │   ├── ResponseActionInterface.php
│   │   ├── AlertChannelInterface.php
│   │   └── SiemProviderInterface.php
│   │
│   ├── MetricsCollector.php
│   ├── DashboardService.php
│   │
│   ├── Anomaly/
│   │   ├── AnomalyDetector.php
│   │   ├── AnomalyResult.php
│   │   ├── Detectors/
│   │   │   ├── ZScoreDetector.php
│   │   │   ├── MovingAverageDetector.php
│   │   │   ├── ThresholdDetector.php
│   │   │   ├── UserBehaviorDetector.php
│   │   │   ├── GeoVelocityDetector.php
│   │   │   ├── SessionAnomalyDetector.php
│   │   │   ├── BruteForceDetector.php
│   │   │   └── CredentialStuffingDetector.php
│   │   └── BaselineManager.php
│   │
│   ├── ThreatIntel/
│   │   ├── ThreatIntelligenceService.php
│   │   ├── ThreatAssessment.php
│   │   ├── Providers/
│   │   │   ├── AbuseIpDbProvider.php
│   │   │   ├── VirusTotalProvider.php
│   │   │   ├── IpQualityScoreProvider.php
│   │   │   ├── GoogleSafeBrowsingProvider.php
│   │   │   └── CustomFeedProvider.php
│   │   └── FeedSynchronizer.php
│   │
│   ├── Response/
│   │   ├── IncidentResponder.php
│   │   ├── ResponsePlaybook.php
│   │   ├── ActionResult.php
│   │   └── Actions/
│   │       ├── LockAccountAction.php
│   │       ├── ForcePasswordResetAction.php
│   │       ├── RevokeSessionsAction.php
│   │       ├── BlockIpAction.php
│   │       ├── RateLimitIpAction.php
│   │       ├── TerminateSessionAction.php
│   │       ├── NotifySecurityTeamAction.php
│   │       └── CreateIncidentTicketAction.php
│   │
│   ├── Alerting/
│   │   ├── AlertManager.php
│   │   ├── SecurityAlert.php
│   │   └── Channels/
│   │       ├── EmailAlertChannel.php
│   │       ├── SlackAlertChannel.php
│   │       ├── TeamsAlertChannel.php
│   │       ├── PagerDutyAlertChannel.php
│   │       ├── OpsGenieAlertChannel.php
│   │       ├── WebhookAlertChannel.php
│   │       └── SmsAlertChannel.php
│   │
│   ├── Reporting/
│   │   ├── ReportGenerator.php
│   │   ├── SecurityReport.php
│   │   └── Reports/
│   │       ├── ExecutiveSummaryReport.php
│   │       ├── ThreatReport.php
│   │       ├── ComplianceReport.php
│   │       ├── IncidentReport.php
│   │       ├── UserActivityReport.php
│   │       └── TrendReport.php
│   │
│   └── Siem/
│       ├── SiemExporter.php
│       ├── EventFormatter.php
│       └── Providers/
│           ├── SplunkHecProvider.php
│           ├── ElasticsearchProvider.php
│           ├── MicrosoftSentinelProvider.php
│           ├── QRadarProvider.php
│           ├── SumoLogicProvider.php
│           ├── DatadogProvider.php
│           ├── SyslogProvider.php
│           └── WebhookProvider.php
│
├── Http/
│   └── Controllers/
│       └── SecurityDashboardController.php
│
├── Models/
│   ├── SecurityMetric.php
│   ├── Anomaly.php
│   ├── UserBehaviorProfile.php
│   ├── ThreatIndicator.php
│   ├── ResponsePlaybook.php
│   ├── SecurityIncident.php
│   ├── AlertRule.php
│   ├── AlertHistory.php
│   └── ScheduledReport.php
│
├── Events/
│   ├── AnomalyDetected.php
│   ├── IncidentCreated.php
│   ├── IncidentResolved.php
│   ├── ThreatDetected.php
│   └── SecurityEventOccurred.php
│
├── Listeners/
│   ├── CollectAuthenticationMetrics.php
│   ├── CollectAuthorizationMetrics.php
│   ├── CollectApiMetrics.php
│   ├── AnalyzeSecurityEvent.php
│   └── ProcessIncidentResponse.php
│
├── Console/
│   └── Commands/
│       ├── AnalyticsProcessCommand.php
│       ├── SyncThreatFeedsCommand.php
│       ├── UpdateBehaviorBaselinesCommand.php
│       ├── GenerateSecurityReportCommand.php
│       ├── PruneAnalyticsDataCommand.php
│       └── TestSiemConnectionCommand.php
│
└── Jobs/
    ├── ProcessSecurityMetrics.php
    ├── AnalyzeAnomalies.php
    ├── ExportToSiem.php
    ├── SendSecurityAlert.php
    └── GenerateScheduledReport.php

database/
└── migrations/
    └── analytics/
        ├── 2025_01_01_000001_create_security_metrics_table.php
        ├── 2025_01_01_000002_create_anomalies_table.php
        ├── 2025_01_01_000003_create_user_behavior_profiles_table.php
        ├── 2025_01_01_000004_create_threat_indicators_table.php
        ├── 2025_01_01_000005_create_response_playbooks_table.php
        ├── 2025_01_01_000006_create_security_incidents_table.php
        ├── 2025_01_01_000007_create_alert_rules_table.php
        ├── 2025_01_01_000008_create_alert_history_table.php
        └── 2025_01_01_000009_create_scheduled_reports_table.php
```

---

## Implementation Order

### Phase 1: Foundation (Core Infrastructure)
1. Create database migrations for all new tables
2. Implement base models (SecurityMetric, Anomaly, etc.)
3. Implement MetricsCollector service
4. Create event listeners for automatic metric collection
5. Add configuration schema

### Phase 2: Anomaly Detection
1. Implement AnomalyDetector service and interface
2. Implement statistical detectors (ZScore, MovingAverage, Threshold)
3. Implement behavioral detectors (UserBehavior, GeoVelocity, Session)
4. Implement rule-based detectors (BruteForce, CredentialStuffing)
5. Create BaselineManager for profile updates
6. Add scheduled command for baseline updates

### Phase 3: Threat Intelligence
1. Implement ThreatIntelligenceService
2. Implement ThreatIndicator model and repository
3. Create provider interface and base class
4. Implement AbuseIPDB provider
5. Implement VirusTotal provider
6. Implement custom feed provider
7. Create feed synchronization command

### Phase 4: Incident Response
1. Implement IncidentResponder service
2. Create ResponsePlaybook model
3. Create SecurityIncident model
4. Implement action interface and base actions
5. Implement user actions (lock, password reset, etc.)
6. Implement IP actions (block, rate limit, etc.)
7. Create default playbooks

### Phase 5: Alerting
1. Implement AlertManager service
2. Create AlertRule and AlertHistory models
3. Implement channel interface
4. Implement Email channel
5. Implement Slack channel
6. Implement PagerDuty/OpsGenie channels
7. Implement Webhook channel
8. Add alert deduplication logic

### Phase 6: Dashboard & Reporting
1. Implement DashboardService
2. Create SecurityDashboardController
3. Implement dashboard API endpoints
4. Add real-time broadcasting support
5. Implement ReportGenerator service
6. Create report templates (Executive, Threat, Compliance, etc.)
7. Add scheduled report functionality

### Phase 7: SIEM Integration
1. Implement SiemExporter service
2. Create EventFormatter for different formats
3. Implement provider interface
4. Implement Splunk HEC provider
5. Implement Elasticsearch provider
6. Implement Syslog provider
7. Implement generic Webhook provider
8. Add batch export and flush functionality

### Phase 8: Testing & Documentation
1. Write unit tests for all services
2. Write feature tests for API endpoints
3. Write integration tests for SIEM providers
4. Create API documentation
5. Create configuration guide
6. Create deployment guide

---

## Dependencies

### Required Packages
- `guzzlehttp/guzzle` - HTTP client for API calls (already installed)
- `league/csv` - CSV export for reports

### Optional Packages (based on features enabled)
- `barryvdh/laravel-dompdf` - PDF report generation
- `pusher/pusher-php-server` - Real-time dashboard (if using Pusher)
- `predis/predis` - Redis support for metrics storage

---

## Security Considerations

1. **Access Control** - Dashboard and API endpoints require proper permissions
2. **Data Retention** - Implement proper retention policies for metrics and logs
3. **Sensitive Data** - Ensure PII is properly handled in reports and exports
4. **API Keys** - Secure storage of third-party API keys (threat intel, SIEM)
5. **Rate Limiting** - Protect dashboard APIs from abuse
6. **Audit Logging** - Log all access to security dashboard and reports

---

## Performance Considerations

1. **Metrics Aggregation** - Pre-aggregate metrics to reduce query load
2. **Async Processing** - Use queues for non-critical processing
3. **Caching** - Cache dashboard data and threat intel lookups
4. **Batch Exports** - Batch SIEM exports to reduce network overhead
5. **Database Indexing** - Proper indexes on frequently queried columns
6. **Data Partitioning** - Consider partitioning large tables by date
