# File Upload Security Implementation Plan

## Overview

This plan outlines the implementation of secure file upload handling with comprehensive validation and threat protection for the ArtisanPackUI Security package.

## Goals

- Prevent malicious file uploads (malware, scripts, executable content)
- Enforce file type and size restrictions
- Provide hooks for external malware scanning services
- Implement secure storage patterns that prevent direct execution
- Rate limit uploads to prevent abuse
- Serve files securely without exposing storage paths
- Comprehensive testing and documentation

---

## 1. Configuration Structure

Add new configuration section to `config/security.php`:

```php
'fileUpload' => [
    'enabled' => true,

    // File type validation
    'allowedMimeTypes' => [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'application/pdf',
        'text/plain',
        'text/csv',
    ],

    'allowedExtensions' => [
        'jpg', 'jpeg', 'png', 'gif', 'webp',
        'pdf', 'txt', 'csv',
    ],

    // Blocked patterns (always rejected regardless of allowed lists)
    'blockedExtensions' => [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps',
        'exe', 'com', 'bat', 'cmd', 'sh', 'bash',
        'js', 'jsx', 'ts', 'tsx',
        'asp', 'aspx', 'jsp', 'cgi', 'pl', 'py', 'rb',
        'htaccess', 'htpasswd',
        'svg',  // Can contain embedded scripts
    ],

    'blockedMimeTypes' => [
        'application/x-httpd-php',
        'application/x-php',
        'text/x-php',
        'application/x-executable',
        'application/x-msdownload',
        'application/javascript',
        'text/javascript',
        'image/svg+xml',  // Can contain embedded scripts
    ],

    // Size restrictions
    'maxFileSize' => 10 * 1024 * 1024, // 10 MB default
    'maxFileSizePerType' => [
        'image/*' => 5 * 1024 * 1024,    // 5 MB for images
        'application/pdf' => 20 * 1024 * 1024, // 20 MB for PDFs
    ],

    // Content validation
    'validateMimeByContent' => true,  // Inspect actual file content, not just extension
    'checkForDoubleExtensions' => true, // Detect file.php.jpg tricks
    'checkForNullBytes' => true,  // Detect file.php%00.jpg tricks
    'stripExifData' => true,  // Remove EXIF metadata from images
    'reencodeImages' => false, // Re-encode images to strip any embedded code

    // Malware scanning
    'malwareScanning' => [
        'enabled' => false,
        'driver' => 'clamav', // clamav, virustotal, custom
        'failOnScanError' => true, // Reject upload if scanner is unavailable
        'async' => false, // Scan asynchronously (quarantine until scanned)
        'quarantinePath' => storage_path('app/quarantine'),
    ],

    // Rate limiting
    'rateLimiting' => [
        'enabled' => true,
        'maxUploadsPerMinute' => 10,
        'maxUploadsPerHour' => 100,
        'maxTotalSizePerHour' => 100 * 1024 * 1024, // 100 MB per hour
    ],

    // Storage
    'storage' => [
        'disk' => 'local',
        'path' => 'uploads',
        'hashFilenames' => true, // Store with hashed names
        'preserveOriginalName' => true, // Store original name in metadata
        'organizeByDate' => true, // Store in YYYY/MM/DD subdirectories
    ],

    // Secure serving
    'serving' => [
        'useSignedUrls' => true,
        'signedUrlExpiration' => 60, // minutes
        'forceDownload' => false, // Force Content-Disposition: attachment
        'allowedReferrers' => [], // Empty = allow all, or list of allowed domains
    ],
],
```

---

## 2. Contracts / Interfaces

### 2.1 FileValidatorInterface

**File:** `src/Contracts/FileValidatorInterface.php`

```php
interface FileValidatorInterface
{
    /**
     * Validate an uploaded file against security rules.
     *
     * @param UploadedFile $file
     * @param array $options Override default configuration
     * @return ValidationResult
     */
    public function validate(UploadedFile $file, array $options = []): ValidationResult;

    /**
     * Check if file extension is allowed.
     */
    public function isExtensionAllowed(string $extension): bool;

    /**
     * Check if MIME type is allowed.
     */
    public function isMimeTypeAllowed(string $mimeType): bool;

    /**
     * Detect actual MIME type from file content.
     */
    public function detectMimeType(UploadedFile $file): string;

    /**
     * Check for dangerous patterns in filename.
     */
    public function hasUnsafeFilename(string $filename): bool;
}
```

### 2.2 MalwareScannerInterface

**File:** `src/Contracts/MalwareScannerInterface.php`

```php
interface MalwareScannerInterface
{
    /**
     * Scan a file for malware.
     *
     * @param string $filePath Absolute path to file
     * @return ScanResult
     */
    public function scan(string $filePath): ScanResult;

    /**
     * Check if scanner service is available.
     */
    public function isAvailable(): bool;

    /**
     * Get scanner name/identifier.
     */
    public function getName(): string;
}
```

### 2.3 SecureFileStorageInterface

**File:** `src/Contracts/SecureFileStorageInterface.php`

```php
interface SecureFileStorageInterface
{
    /**
     * Store a validated file securely.
     *
     * @param UploadedFile $file
     * @param array $options
     * @return StoredFile
     */
    public function store(UploadedFile $file, array $options = []): StoredFile;

    /**
     * Retrieve a stored file.
     *
     * @param string $identifier
     * @return StoredFile|null
     */
    public function retrieve(string $identifier): ?StoredFile;

    /**
     * Delete a stored file.
     */
    public function delete(string $identifier): bool;

    /**
     * Generate a secure URL for file access.
     */
    public function generateSecureUrl(string $identifier, ?int $expirationMinutes = null): string;
}
```

---

## 3. Value Objects / DTOs

### 3.1 ValidationResult

**File:** `src/FileUpload/ValidationResult.php`

```php
class ValidationResult
{
    public function __construct(
        public readonly bool $passed,
        public readonly array $errors = [],
        public readonly ?string $detectedMimeType = null,
        public readonly ?string $sanitizedFilename = null,
    ) {}

    public function failed(): bool;
    public function getErrors(): array;
}
```

### 3.2 ScanResult

**File:** `src/FileUpload/ScanResult.php`

```php
class ScanResult
{
    public const STATUS_CLEAN = 'clean';
    public const STATUS_INFECTED = 'infected';
    public const STATUS_ERROR = 'error';
    public const STATUS_PENDING = 'pending';

    public function __construct(
        public readonly string $status,
        public readonly ?string $threatName = null,
        public readonly ?string $scannerName = null,
        public readonly ?array $metadata = [],
    ) {}

    public function isClean(): bool;
    public function isInfected(): bool;
}
```

### 3.3 StoredFile

**File:** `src/FileUpload/StoredFile.php`

```php
class StoredFile
{
    public function __construct(
        public readonly string $identifier,
        public readonly string $originalName,
        public readonly string $storagePath,
        public readonly string $mimeType,
        public readonly int $size,
        public readonly string $hash,
        public readonly ?array $metadata = [],
    ) {}

    public function toArray(): array;
    public static function fromArray(array $data): self;
}
```

---

## 4. Services

### 4.1 FileValidationService

**File:** `src/Services/FileValidationService.php`

Responsibilities:
- Validate file extension against allowlist/blocklist
- Validate MIME type against allowlist/blocklist
- Detect actual MIME type from file content (using `finfo`)
- Check for double extensions (e.g., `file.php.jpg`)
- Check for null byte injection in filename
- Validate file size against limits
- Sanitize filename for safe storage

Key methods:
```php
class FileValidationService implements FileValidatorInterface
{
    public function validate(UploadedFile $file, array $options = []): ValidationResult;
    public function isExtensionAllowed(string $extension): bool;
    public function isMimeTypeAllowed(string $mimeType): bool;
    public function detectMimeType(UploadedFile $file): string;
    public function hasUnsafeFilename(string $filename): bool;

    protected function checkDoubleExtension(string $filename): bool;
    protected function checkNullBytes(string $filename): bool;
    protected function sanitizeFilename(string $filename): string;
    protected function validateSize(UploadedFile $file): ?string;
    protected function mimeMatchesExtension(string $mimeType, string $extension): bool;
}
```

### 4.2 ClamAvScanner

**File:** `src/Services/Scanners/ClamAvScanner.php`

Integration with ClamAV antivirus:
- Connect via socket or command line (`clamscan`)
- Support for clamd daemon mode for performance
- Handle timeout and connection errors gracefully

```php
class ClamAvScanner implements MalwareScannerInterface
{
    public function __construct(
        private string $socketPath = '/var/run/clamav/clamd.sock',
        private ?string $binaryPath = '/usr/bin/clamscan',
        private int $timeout = 30,
    ) {}

    public function scan(string $filePath): ScanResult;
    public function isAvailable(): bool;
    public function getName(): string;

    protected function scanViaSocket(string $filePath): ScanResult;
    protected function scanViaBinary(string $filePath): ScanResult;
}
```

### 4.3 VirusTotalScanner

**File:** `src/Services/Scanners/VirusTotalScanner.php`

Integration with VirusTotal API:
- Submit file hash first (avoids uploading if already scanned)
- Upload file if hash not found
- Handle rate limiting (4 requests/minute for free tier)
- Support async scanning with webhook callbacks

```php
class VirusTotalScanner implements MalwareScannerInterface
{
    public function __construct(
        private string $apiKey,
        private HttpClientInterface $httpClient,
        private ?CacheInterface $cache = null,
    ) {}

    public function scan(string $filePath): ScanResult;
    public function scanByHash(string $hash): ?ScanResult;
    public function isAvailable(): bool;
    public function getName(): string;
}
```

### 4.4 NullScanner

**File:** `src/Services/Scanners/NullScanner.php`

No-op scanner for when malware scanning is disabled:

```php
class NullScanner implements MalwareScannerInterface
{
    public function scan(string $filePath): ScanResult
    {
        return new ScanResult(ScanResult::STATUS_CLEAN);
    }

    public function isAvailable(): bool
    {
        return true;
    }
}
```

### 4.5 SecureFileStorageService

**File:** `src/Services/SecureFileStorageService.php`

Responsibilities:
- Generate secure, hashed filenames
- Organize files in date-based directories
- Store metadata (original name, upload time, user)
- Strip EXIF data from images
- Generate signed URLs for secure access

```php
class SecureFileStorageService implements SecureFileStorageInterface
{
    public function __construct(
        private FilesystemManager $filesystem,
        private FileValidatorInterface $validator,
        private ?MalwareScannerInterface $scanner = null,
    ) {}

    public function store(UploadedFile $file, array $options = []): StoredFile;
    public function retrieve(string $identifier): ?StoredFile;
    public function delete(string $identifier): bool;
    public function generateSecureUrl(string $identifier, ?int $expirationMinutes = null): string;

    protected function generateStoragePath(): string;
    protected function generateSecureFilename(UploadedFile $file): string;
    protected function stripExifData(string $filePath): void;
    protected function storeMetadata(StoredFile $file): void;
}
```

### 4.6 FileUploadRateLimiter

**File:** `src/Services/FileUploadRateLimiter.php`

```php
class FileUploadRateLimiter
{
    public function __construct(
        private RateLimiter $limiter,
        private ?CacheInterface $cache = null,
    ) {}

    public function attempt(Request $request, int $fileSize): bool;
    public function tooManyAttempts(Request $request): bool;
    public function availableIn(Request $request): int;

    protected function getKey(Request $request): string;
    protected function checkSizeLimit(Request $request, int $fileSize): bool;
}
```

---

## 5. Middleware

### 5.1 ValidateFileUpload

**File:** `src/Http/Middleware/ValidateFileUpload.php`

Main middleware that orchestrates file validation:

```php
class ValidateFileUpload
{
    public function __construct(
        private FileValidatorInterface $validator,
        private FileUploadRateLimiter $rateLimiter,
    ) {}

    public function handle(Request $request, Closure $next, ...$allowedTypes): Response
    {
        // 1. Check rate limiting
        // 2. Get uploaded files from request
        // 3. Validate each file
        // 4. Reject if any validation fails
        // 5. Attach validation results to request for downstream use
    }
}
```

Usage in routes:
```php
Route::post('/upload', [UploadController::class, 'store'])
    ->middleware('validate.upload:image/*,application/pdf');
```

### 5.2 ScanUploadedFiles

**File:** `src/Http/Middleware/ScanUploadedFiles.php`

Middleware for malware scanning (can be used separately):

```php
class ScanUploadedFiles
{
    public function __construct(
        private MalwareScannerInterface $scanner,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        // 1. Get uploaded files
        // 2. Scan each file
        // 3. Quarantine or reject infected files
        // 4. Log scan results
    }
}
```

---

## 6. Validation Rules

### 6.1 SecureFile

**File:** `src/Rules/SecureFile.php`

Laravel validation rule for use in form requests:

```php
class SecureFile implements Rule
{
    public function __construct(
        private array $allowedMimeTypes = [],
        private ?int $maxSize = null,
        private bool $scanForMalware = false,
    ) {}

    public function passes($attribute, $value): bool;
    public function message(): string|array;

    // Fluent configuration
    public function types(array $mimeTypes): self;
    public function maxSize(int $bytes): self;
    public function scanMalware(bool $scan = true): self;
}
```

Usage:
```php
$request->validate([
    'avatar' => [
        'required',
        new SecureFile()
            ->types(['image/jpeg', 'image/png'])
            ->maxSize(2 * 1024 * 1024)
            ->scanMalware(),
    ],
]);
```

### 6.2 SafeFilename

**File:** `src/Rules/SafeFilename.php`

Validates that a filename is safe:

```php
class SafeFilename implements Rule
{
    public function passes($attribute, $value): bool
    {
        // Check for path traversal
        // Check for null bytes
        // Check for double extensions
        // Check for reserved names (Windows)
    }

    public function message(): string;
}
```

---

## 7. Controller / Route for Secure File Serving

### 7.1 SecureFileController

**File:** `src/Http/Controllers/SecureFileController.php`

```php
class SecureFileController extends Controller
{
    public function __construct(
        private SecureFileStorageInterface $storage,
    ) {}

    /**
     * Serve a file via signed URL.
     */
    public function show(Request $request, string $identifier): Response
    {
        // 1. Validate signed URL
        // 2. Check referrer if configured
        // 3. Retrieve file
        // 4. Return with appropriate headers
    }

    /**
     * Download a file via signed URL.
     */
    public function download(Request $request, string $identifier): Response
    {
        // Force Content-Disposition: attachment
    }
}
```

### 7.2 Routes

**File:** `routes/security.php` (addition)

```php
Route::middleware(['web', 'signed'])->group(function () {
    Route::get('/secure-file/{identifier}', [SecureFileController::class, 'show'])
        ->name('secure-file.show');
    Route::get('/secure-file/{identifier}/download', [SecureFileController::class, 'download'])
        ->name('secure-file.download');
});
```

---

## 8. Events

### 8.1 FileUploaded

**File:** `src/Events/FileUploaded.php`

Dispatched when a file is successfully uploaded and stored:

```php
class FileUploaded
{
    public function __construct(
        public readonly StoredFile $file,
        public readonly ?Authenticatable $user,
        public readonly Request $request,
    ) {}
}
```

### 8.2 FileUploadRejected

**File:** `src/Events/FileUploadRejected.php`

Dispatched when a file upload is rejected:

```php
class FileUploadRejected
{
    public function __construct(
        public readonly string $originalName,
        public readonly array $reasons,
        public readonly ?Authenticatable $user,
        public readonly Request $request,
    ) {}
}
```

### 8.3 MalwareDetected

**File:** `src/Events/MalwareDetected.php`

Dispatched when malware is detected in an upload:

```php
class MalwareDetected
{
    public function __construct(
        public readonly string $originalName,
        public readonly ScanResult $scanResult,
        public readonly ?Authenticatable $user,
        public readonly Request $request,
    ) {}
}
```

### 8.4 FileServed

**File:** `src/Events/FileServed.php`

Dispatched when a file is accessed via secure URL:

```php
class FileServed
{
    public function __construct(
        public readonly StoredFile $file,
        public readonly ?Authenticatable $user,
        public readonly Request $request,
    ) {}
}
```

---

## 9. Database

### 9.1 Migration: Create Uploaded Files Table

**File:** `database/migrations/uploads/2025_12_23_000001_create_secure_files_table.php`

```php
Schema::create('secure_files', function (Blueprint $table) {
    $table->id();
    $table->uuid('identifier')->unique();
    $table->string('original_name');
    $table->string('storage_path');
    $table->string('disk')->default('local');
    $table->string('mime_type');
    $table->unsignedBigInteger('size');
    $table->string('hash', 64); // SHA-256
    $table->foreignId('uploaded_by')->nullable()->constrained('users')->nullOnDelete();
    $table->string('scan_status')->default('pending'); // pending, clean, infected, error
    $table->string('threat_name')->nullable();
    $table->timestamp('scanned_at')->nullable();
    $table->json('metadata')->nullable();
    $table->timestamps();
    $table->softDeletes();

    $table->index('hash');
    $table->index('scan_status');
    $table->index('uploaded_by');
});
```

### 9.2 Model: SecureFile

**File:** `src/Models/SecureFile.php`

```php
class SecureFile extends Model
{
    use HasUuids, SoftDeletes;

    protected $casts = [
        'size' => 'integer',
        'metadata' => 'array',
        'scanned_at' => 'datetime',
    ];

    public function uploadedBy(): BelongsTo;
    public function getSecureUrl(?int $expirationMinutes = null): string;
    public function getDownloadUrl(?int $expirationMinutes = null): string;
    public function markAsClean(): void;
    public function markAsInfected(string $threatName): void;
    public function scopeClean(Builder $query): Builder;
    public function scopePendingScan(Builder $query): Builder;
}
```

---

## 10. Service Provider Updates

**File:** `src/SecurityServiceProvider.php` (additions)

```php
// Register bindings
$this->app->singleton(FileValidatorInterface::class, FileValidationService::class);
$this->app->singleton(SecureFileStorageInterface::class, SecureFileStorageService::class);

// Register malware scanner based on config
$this->app->singleton(MalwareScannerInterface::class, function ($app) {
    $driver = config('artisanpack.security.fileUpload.malwareScanning.driver');

    return match ($driver) {
        'clamav' => new ClamAvScanner(),
        'virustotal' => new VirusTotalScanner(
            config('services.virustotal.api_key'),
            $app->make(HttpClientInterface::class),
        ),
        default => new NullScanner(),
    };
});

// Register middleware aliases
$router->aliasMiddleware('validate.upload', ValidateFileUpload::class);
$router->aliasMiddleware('scan.upload', ScanUploadedFiles::class);

// Register validation rules
Validator::extend('secure_file', function ($attribute, $value, $parameters) {
    return (new SecureFile())->passes($attribute, $value);
});
```

---

## 11. Helper Trait for Models

### 11.1 HasSecureFiles

**File:** `src/Concerns/HasSecureFiles.php`

Trait for models that have file attachments:

```php
trait HasSecureFiles
{
    public function secureFiles(): MorphMany
    {
        return $this->morphMany(SecureFile::class, 'fileable');
    }

    public function attachSecureFile(UploadedFile $file, array $options = []): StoredFile
    {
        $storage = app(SecureFileStorageInterface::class);
        return $storage->store($file, array_merge($options, [
            'fileable_type' => static::class,
            'fileable_id' => $this->getKey(),
        ]));
    }
}
```

---

## 12. Console Commands

### 12.1 ScanQuarantinedFiles

**File:** `src/Console/Commands/ScanQuarantinedFiles.php`

Process files in quarantine (for async scanning):

```php
class ScanQuarantinedFiles extends Command
{
    protected $signature = 'security:scan-quarantine {--limit=100}';
    protected $description = 'Scan quarantined files for malware';

    public function handle(): int;
}
```

### 12.2 CleanupExpiredFiles

**File:** `src/Console/Commands/CleanupExpiredFiles.php`

Remove old/expired uploaded files:

```php
class CleanupExpiredFiles extends Command
{
    protected $signature = 'security:cleanup-files {--days=30}';
    protected $description = 'Remove expired uploaded files';

    public function handle(): int;
}
```

---

## 13. Testing Plan

### 13.1 Unit Tests

**File:** `tests/Unit/FileValidationServiceTest.php`
- Test extension validation (allowed/blocked)
- Test MIME type validation
- Test double extension detection
- Test null byte detection
- Test filename sanitization
- Test file size limits
- Test MIME type detection from content

**File:** `tests/Unit/ClamAvScannerTest.php`
- Test clean file detection
- Test infected file detection
- Test scanner unavailable handling
- Test timeout handling

**File:** `tests/Unit/SecureFileStorageServiceTest.php`
- Test file storage with hashed names
- Test date-based organization
- Test metadata storage
- Test signed URL generation
- Test file retrieval and deletion

**File:** `tests/Unit/FileUploadRateLimiterTest.php`
- Test per-minute limits
- Test per-hour limits
- Test size-based limits
- Test limit reset

### 13.2 Feature Tests

**File:** `tests/Feature/FileUploadSecurityTest.php`
- Test successful file upload flow
- Test rejection of blocked extensions
- Test rejection of blocked MIME types
- Test rejection of oversized files
- Test double extension rejection
- Test rate limiting enforcement
- Test malware rejection (with mock scanner)
- Test secure file serving
- Test signed URL expiration
- Test referrer checking

### 13.3 Integration Tests

**File:** `tests/Integration/MalwareScanningTest.php`
- Test ClamAV integration (if available)
- Test VirusTotal integration (with test API key)
- Test quarantine workflow

---

## 14. Documentation

### 14.1 README Section

Add comprehensive documentation covering:
- Configuration options explained
- Middleware usage examples
- Validation rule usage
- Malware scanner setup (ClamAV, VirusTotal)
- Custom scanner implementation
- Secure file serving patterns
- Event handling examples
- Rate limiting configuration
- Testing uploaded files

### 14.2 Example Usage

```php
// In a controller
public function store(Request $request)
{
    $request->validate([
        'document' => [
            'required',
            new SecureFile()
                ->types(['application/pdf', 'image/*'])
                ->maxSize(10 * 1024 * 1024),
        ],
    ]);

    $storage = app(SecureFileStorageInterface::class);
    $storedFile = $storage->store($request->file('document'));

    return response()->json([
        'url' => $storedFile->getSecureUrl(60), // 60-minute expiry
    ]);
}

// Using middleware
Route::post('/upload', [UploadController::class, 'store'])
    ->middleware(['auth', 'validate.upload:image/*,application/pdf']);

// Serving files
<a href="{{ $file->getSecureUrl() }}">Download File</a>
```

---

## 15. Implementation Order

1. **Phase 1: Core Validation**
   - Configuration structure
   - FileValidatorInterface and FileValidationService
   - ValidationResult value object
   - SecureFile validation rule
   - SafeFilename validation rule

2. **Phase 2: Storage**
   - Database migration
   - SecureFile model
   - SecureFileStorageInterface and SecureFileStorageService
   - StoredFile value object
   - HasSecureFiles trait

3. **Phase 3: Middleware**
   - ValidateFileUpload middleware
   - FileUploadRateLimiter service
   - Rate limiting tests

4. **Phase 4: Malware Scanning**
   - MalwareScannerInterface
   - ScanResult value object
   - NullScanner (default)
   - ClamAvScanner
   - VirusTotalScanner
   - ScanUploadedFiles middleware
   - Quarantine workflow

5. **Phase 5: Secure Serving**
   - SecureFileController
   - Signed URL routes
   - Referrer checking

6. **Phase 6: Events & Commands**
   - All event classes
   - Console commands
   - Service provider registration

7. **Phase 7: Testing & Documentation**
   - Complete test suite
   - Documentation
   - Example implementations

---

## 16. Security Considerations

### File Storage
- Store files outside web root (use `storage/app`, not `public`)
- Never serve files directly via web server
- Use randomized/hashed filenames to prevent enumeration
- Set restrictive file permissions (0640)

### Content Validation
- Always validate MIME type from file content, not extension
- Strip metadata (EXIF) which can contain malicious content
- Consider re-encoding images to remove embedded payloads
- Check for polyglot files (files that are valid in multiple formats)

### Access Control
- Use signed URLs with short expiration times
- Log all file access for audit trails
- Implement per-user and per-file access controls
- Check referrer headers to prevent hotlinking

### Malware Prevention
- Integrate with antivirus scanning
- Quarantine files until scanned in high-security environments
- Block executable content regardless of extension
- Monitor for suspicious upload patterns

---

## 17. Media-Library Package Integration

The `artisanpack-ui/media-library` package already depends on `artisanpack-ui/security`. This section outlines how the file upload security features integrate seamlessly with the media-library.

### 17.1 Integration Philosophy

The security package provides **building blocks** that media-library can use:

| Security Package Provides | Media-Library Uses It For |
|--------------------------|---------------------------|
| `FileValidatorInterface` | Pre-storage validation in `MediaUploadService` |
| `MalwareScannerInterface` | Optional scanning before storage |
| `SecureFile` validation rule | In `MediaStoreRequest` rules |
| `FileUploadRateLimiter` | Rate limiting on `/api/media` routes |
| Security events | Audit logging via event listeners |
| EXIF stripping | Image privacy/security |

**Key Principle:** Media-library handles storage and organization; security package handles threat prevention.

### 17.2 Configuration Bridging

The security package should respect media-library's existing configuration when used together:

**File:** `src/Services/FileValidationService.php`

```php
public function __construct()
{
    // If media-library config exists, use it as defaults
    $this->allowedMimeTypes = config(
        'artisanpack.security.fileUpload.allowedMimeTypes',
        config('artisanpack.media.allowed_mime_types', [])
    );

    $this->maxFileSize = config(
        'artisanpack.security.fileUpload.maxFileSize',
        config('artisanpack.media.max_file_size', 10240) * 1024
    );
}
```

Add helper method to bridge configurations:

```php
// In FileValidationService
public function withMediaLibraryDefaults(): self
{
    if (config('artisanpack.media')) {
        $this->allowedMimeTypes = array_merge(
            $this->allowedMimeTypes,
            config('artisanpack.media.allowed_mime_types', [])
        );
    }
    return $this;
}
```

### 17.3 Service Integration

Media-library's `MediaUploadService` can integrate security validation:

**Recommended changes to media-library** (`MediaUploadService.php`):

```php
use ArtisanPackUI\Security\Contracts\FileValidatorInterface;
use ArtisanPackUI\Security\Contracts\MalwareScannerInterface;

class MediaUploadService
{
    public function __construct(
        private MediaStorageService $storage,
        private ?FileValidatorInterface $securityValidator = null,
        private ?MalwareScannerInterface $malwareScanner = null,
    ) {
        // Auto-resolve from container if available
        $this->securityValidator ??= app()->bound(FileValidatorInterface::class)
            ? app(FileValidatorInterface::class)
            : null;

        $this->malwareScanner ??= app()->bound(MalwareScannerInterface::class)
            ? app(MalwareScannerInterface::class)
            : null;
    }

    public function upload(UploadedFile $file, array $options = []): Media
    {
        // Security validation (if security package is installed)
        if ($this->securityValidator && config('artisanpack.security.fileUpload.enabled', false)) {
            $result = $this->securityValidator->validate($file, [
                'allowedMimeTypes' => config('artisanpack.media.allowed_mime_types'),
                'maxFileSize' => config('artisanpack.media.max_file_size') * 1024,
            ]);

            if ($result->failed()) {
                throw new FileValidationException($result->getErrors());
            }
        }

        // Malware scanning (if enabled)
        if ($this->malwareScanner && config('artisanpack.security.fileUpload.malwareScanning.enabled', false)) {
            $scanResult = $this->malwareScanner->scan($file->getPathname());

            if ($scanResult->isInfected()) {
                event(new \ArtisanPackUI\Security\Events\MalwareDetected(
                    $file->getClientOriginalName(),
                    $scanResult,
                    auth()->user(),
                    request()
                ));

                throw new MalwareDetectedException($scanResult->threatName);
            }
        }

        // Continue with existing upload logic...
        return $this->processUpload($file, $options);
    }
}
```

### 17.4 Validation Rule Integration

Media-library's `MediaStoreRequest` can use security validation rules:

**Recommended changes to media-library** (`MediaStoreRequest.php`):

```php
use ArtisanPackUI\Security\Rules\SecureFile;

class MediaStoreRequest extends FormRequest
{
    public function rules(): array
    {
        $rules = [
            'title' => ['nullable', 'string', 'max:255'],
            'alt_text' => ['nullable', 'string', 'max:255'],
            // ... other rules
        ];

        // Use security package's SecureFile rule if available
        if (class_exists(SecureFile::class)) {
            $rules['file'] = [
                'required',
                'file',
                (new SecureFile())
                    ->types(config('artisanpack.media.allowed_mime_types', []))
                    ->maxSize(config('artisanpack.media.max_file_size', 10240) * 1024),
            ];
        } else {
            // Fallback to basic validation
            $rules['file'] = [
                'required',
                'file',
                'max:' . config('artisanpack.media.max_file_size', 10240),
                'mimes:' . $this->getAllowedExtensions(),
            ];
        }

        return $rules;
    }
}
```

### 17.5 Middleware Integration

Apply security middleware to media-library routes:

**Option A: Media-library registers security middleware** (in `MediaLibraryServiceProvider`):

```php
public function boot(): void
{
    // ... existing boot code

    // Apply security middleware if available
    if (class_exists(\ArtisanPackUI\Security\Http\Middleware\ValidateFileUpload::class)) {
        $this->app['router']->pushMiddlewareToGroup('api', 'validate.upload');
    }
}
```

**Option B: Explicit route middleware** (in media-library's `api.php`):

```php
Route::middleware(['auth:sanctum'])
    ->prefix('api/media')
    ->group(function () {
        // Apply upload validation only to POST routes
        Route::post('/', [MediaController::class, 'store'])
            ->middleware(array_filter([
                class_exists(ValidateFileUpload::class) ? 'validate.upload' : null,
                class_exists(FileUploadRateLimiter::class) ? 'throttle.upload' : null,
            ]));

        // Other routes without upload middleware
        Route::get('/', [MediaController::class, 'index']);
        Route::get('/{media}', [MediaController::class, 'show']);
        // ...
    });
```

### 17.6 Event Integration

Security events can trigger media-library actions:

**In media-library's `EventServiceProvider`:**

```php
protected $listen = [
    // Listen to security events
    \ArtisanPackUI\Security\Events\MalwareDetected::class => [
        \App\Listeners\LogMalwareAttempt::class,
        \App\Listeners\NotifyAdminOfMalware::class,
    ],

    \ArtisanPackUI\Security\Events\FileUploadRejected::class => [
        \App\Listeners\LogRejectedUpload::class,
    ],
];
```

**Media-library can dispatch security events:**

```php
// In MediaUploadService after successful upload
event(new \ArtisanPackUI\Security\Events\FileUploaded(
    new StoredFile(
        identifier: $media->id,
        originalName: $media->file_name,
        storagePath: $media->file_path,
        mimeType: $media->mime_type,
        size: $media->file_size,
        hash: hash_file('sha256', $media->getPath()),
    ),
    auth()->user(),
    request()
));
```

### 17.7 EXIF Stripping Integration

Media-library's `MediaProcessingService` can use security's EXIF stripping:

```php
use ArtisanPackUI\Security\Services\FileValidationService;

class MediaProcessingService
{
    public function processImage(string $path): void
    {
        // Strip EXIF if security package is configured to do so
        if (config('artisanpack.security.fileUpload.stripExifData', false)) {
            $validator = app(FileValidatorInterface::class);
            if (method_exists($validator, 'stripExifData')) {
                $validator->stripExifData($path);
            }
        }

        // Continue with existing image processing...
    }
}
```

### 17.8 Storage Considerations

Media-library manages its own storage via `MediaStorageService`. The security package's `SecureFileStorageService` is **not** meant to replace it, but to provide:

1. **Standalone secure storage** - For non-media files (documents, exports, etc.)
2. **Security utilities** - EXIF stripping, filename sanitization, hash generation

**Recommended approach:**

```php
// Media-library continues to use its own storage
$media = $mediaUploadService->upload($file); // Uses MediaStorageService

// Security features are applied during validation, not storage
// Media-library stores files; security package validates them first
```

### 17.9 Signed URLs for Private Media

Media-library can optionally use security package's signed URLs for private files:

**Add to Media model:**

```php
use ArtisanPackUI\Security\Contracts\SecureFileStorageInterface;

class Media extends Model
{
    /**
     * Get a signed URL for private media access.
     */
    public function getSignedUrl(?int $expirationMinutes = null): string
    {
        if (app()->bound(SecureFileStorageInterface::class)) {
            return app(SecureFileStorageInterface::class)
                ->generateSecureUrl($this->id, $expirationMinutes);
        }

        // Fallback to Laravel's signed URLs
        return URL::temporarySignedRoute(
            'media.show',
            now()->addMinutes($expirationMinutes ?? 60),
            ['media' => $this->id]
        );
    }

    /**
     * Check if this media should use signed URLs.
     */
    public function requiresSignedUrl(): bool
    {
        // Private disk or sensitive MIME types
        return $this->disk !== 'public'
            || in_array($this->mime_type, config('artisanpack.media.private_mime_types', []));
    }
}
```

### 17.10 Integration Testing

**File:** `tests/Feature/MediaLibrarySecurityIntegrationTest.php`

```php
class MediaLibrarySecurityIntegrationTest extends TestCase
{
    #[Test]
    public function it_rejects_dangerous_file_types_via_media_upload()
    {
        $file = UploadedFile::fake()->create('malicious.php', 100);

        $response = $this->actingAs($this->user)
            ->postJson('/api/media', ['file' => $file]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['file']);
    }

    #[Test]
    public function it_applies_rate_limiting_to_media_uploads()
    {
        $file = UploadedFile::fake()->image('photo.jpg');

        // Exceed rate limit
        for ($i = 0; $i < 15; $i++) {
            $this->actingAs($this->user)
                ->postJson('/api/media', ['file' => $file]);
        }

        $response = $this->actingAs($this->user)
            ->postJson('/api/media', ['file' => $file]);

        $response->assertStatus(429);
    }

    #[Test]
    public function it_strips_exif_data_from_uploaded_images()
    {
        config(['artisanpack.security.fileUpload.stripExifData' => true]);

        $file = UploadedFile::fake()->image('photo.jpg');

        $response = $this->actingAs($this->user)
            ->postJson('/api/media', ['file' => $file]);

        $response->assertSuccessful();

        $media = Media::latest()->first();
        $exif = @exif_read_data($media->getPath());

        $this->assertEmpty($exif);
    }
}
```

### 17.11 Integration Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Request Flow                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. HTTP Request (POST /api/media)                                  │
│         │                                                            │
│         ▼                                                            │
│  2. Rate Limiting Middleware (security package)                     │
│         │                                                            │
│         ▼                                                            │
│  3. MediaStoreRequest validation                                    │
│         │── Uses SecureFile rule (security package)                 │
│         │── Validates MIME types, size, extensions                  │
│         │── Checks for dangerous patterns                           │
│         │                                                            │
│         ▼                                                            │
│  4. MediaController::store()                                        │
│         │                                                            │
│         ▼                                                            │
│  5. MediaUploadService::upload()                                    │
│         │── FileValidatorInterface::validate() (security)           │
│         │── MalwareScannerInterface::scan() (security, optional)    │
│         │── Strip EXIF data (security)                              │
│         │                                                            │
│         ▼                                                            │
│  6. MediaStorageService::store() (media-library)                    │
│         │── Generates filename                                       │
│         │── Stores to configured disk                               │
│         │                                                            │
│         ▼                                                            │
│  7. Media model created                                             │
│         │                                                            │
│         ▼                                                            │
│  8. FileUploaded event dispatched (security)                        │
│         │                                                            │
│         ▼                                                            │
│  9. Response returned                                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 17.12 Configuration Example

Complete configuration when both packages are installed:

```php
// config/artisanpack/security.php
'fileUpload' => [
    'enabled' => true,

    // These will be merged with media-library config if not set
    'allowedMimeTypes' => null, // Falls back to artisanpack.media.allowed_mime_types
    'maxFileSize' => null, // Falls back to artisanpack.media.max_file_size

    // Security-specific settings (always applied)
    'blockedExtensions' => ['php', 'exe', 'sh', ...],
    'blockedMimeTypes' => ['application/x-php', ...],
    'validateMimeByContent' => true,
    'checkForDoubleExtensions' => true,
    'stripExifData' => true,

    'malwareScanning' => [
        'enabled' => true,
        'driver' => 'clamav',
    ],

    'rateLimiting' => [
        'enabled' => true,
        'maxUploadsPerMinute' => 10,
    ],
],

// config/artisanpack/media.php
'allowed_mime_types' => [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/webm',
    'application/pdf',
],
'max_file_size' => 10240, // KB
```

---

## Acceptance Criteria Checklist

- [ ] Implement file type validation middleware (`ValidateFileUpload`)
- [ ] Add file size restriction enforcement (`FileValidationService`)
- [ ] Create malware scanning integration hooks (`MalwareScannerInterface`, `ClamAvScanner`, `VirusTotalScanner`)
- [ ] Implement secure file storage patterns (`SecureFileStorageService`)
- [ ] Add file upload rate limiting (`FileUploadRateLimiter`)
- [ ] Create secure file serving mechanisms (`SecureFileController`, signed URLs)
- [ ] Add file upload security testing (comprehensive test suite)
- [ ] Document secure upload patterns (README documentation)
- [ ] Ensure media-library integration works seamlessly (configuration bridging, service integration)
