<?php

/**
 * DependencyScanner security scanner.
 *
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      2.0.0
 */

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\Scanners;

use ArtisanPackUI\Security\Testing\Reporting\SecurityFinding;
use Composer\Semver\Semver;
use Exception;
use Illuminate\Support\Facades\File;

class DependencyScanner implements ScannerInterface
{
    /**
     * @var array<SecurityFinding>
     */
    protected array $findings = [];

    /**
     * Path to advisory database (optional).
     */
    protected ?string $advisoryDatabase = null;

    public function __construct(
        protected string $composerLockPath = 'composer.lock',
        protected string $packageLockPath = 'package-lock.json',
    ) {
        $this->composerLockPath = base_path($composerLockPath);
        $this->packageLockPath  = base_path($packageLockPath);
    }

    public function scan(): array
    {
        $this->findings = [];

        $this->scanComposerDependencies();
        $this->scanNpmDependencies();

        return $this->findings;
    }

    public function getName(): string
    {
        return 'Dependency Scanner';
    }

    public function getDescription(): string
    {
        return 'Scans composer and npm dependencies for known vulnerabilities';
    }

    /**
     * Set a local advisory database path.
     */
    public function useLocalAdvisories(string $path): self
    {
        $this->advisoryDatabase = $path;

        return $this;
    }

    /**
     * Scan Composer dependencies for vulnerabilities.
     */
    protected function scanComposerDependencies(): void
    {
        if (! File::exists($this->composerLockPath)) {
            $this->findings[] = SecurityFinding::info(
                'composer.lock Not Found',
                'Cannot scan Composer dependencies without composer.lock',
                'A06:2021-Vulnerable and Outdated Components',
                base_path(),
                'Run composer install to generate composer.lock',
            );

            return;
        }

        $lock = json_decode(File::get($this->composerLockPath), true);

        if (JSON_ERROR_NONE !== json_last_error()) {
            $this->findings[] = SecurityFinding::medium(
                'Invalid composer.lock',
                'composer.lock file is not valid JSON',
                'A06:2021-Vulnerable and Outdated Components',
                $this->composerLockPath,
            );

            return;
        }

        $packages = array_merge(
            $lock['packages'] ?? [],
            $lock['packages-dev'] ?? [],
        );

        // Check against local advisories if available
        $advisories = $this->loadAdvisories();

        foreach ($packages as $package) {
            $name    = $package['name'] ?? '';
            $version = $package['version'] ?? '';

            // Check against known vulnerabilities
            $vulnerabilities = $this->checkPackageVulnerabilities($name, $version, $advisories);

            foreach ($vulnerabilities as $vuln) {
                $this->findings[] = SecurityFinding::fromVulnerability($vuln);
            }

            // Check for abandoned packages
            if (isset($package['abandoned'])) {
                $replacement      = is_string($package['abandoned']) ? $package['abandoned'] : 'unknown';
                $this->findings[] = SecurityFinding::medium(
                    'Abandoned Package',
                    "Package '{$name}' is abandoned".('unknown' !== $replacement ? ", suggested replacement: {$replacement}" : ''),
                    'A06:2021-Vulnerable and Outdated Components',
                    $this->composerLockPath,
                    "Replace '{$name}' with an actively maintained alternative",
                );
            }
        }

        // Check for outdated packages (based on version constraints)
        $this->checkOutdatedPackages($packages);
    }

    /**
     * Scan NPM dependencies for vulnerabilities.
     */
    protected function scanNpmDependencies(): void
    {
        if (! File::exists($this->packageLockPath)) {
            return; // NPM dependencies are optional
        }

        $lock = json_decode(File::get($this->packageLockPath), true);

        if (JSON_ERROR_NONE !== json_last_error()) {
            $this->findings[] = SecurityFinding::medium(
                'Invalid package-lock.json',
                'package-lock.json file is not valid JSON',
                'A06:2021-Vulnerable and Outdated Components',
                $this->packageLockPath,
            );

            return;
        }

        // Get packages from lockfile v2/v3 format
        $packages = $lock['packages'] ?? [];

        // Check each package
        foreach ($packages as $path => $package) {
            if ('' === $path) {
                continue; // Skip root package
            }

            $name    = str_replace('node_modules/', '', $path);
            $version = $package['version'] ?? '';

            // Basic check for known vulnerable packages
            $vulnerabilities = $this->checkNpmVulnerabilities($name, $version);

            foreach ($vulnerabilities as $vuln) {
                $this->findings[] = SecurityFinding::fromVulnerability($vuln);
            }
        }
    }

    /**
     * Load security advisories from local database.
     *
     * @return array<string, array<array<string, mixed>>>
     */
    protected function loadAdvisories(): array
    {
        if ($this->advisoryDatabase && File::exists($this->advisoryDatabase)) {
            $content = File::get($this->advisoryDatabase);
            $data    = json_decode($content, true);

            return $data ?? [];
        }

        // Default known vulnerable packages (subset for demonstration)
        return [
            'symfony/http-foundation' => [
                [
                    'cve'               => 'CVE-2022-24894',
                    'title'             => 'Cookie Parsing Vulnerability',
                    'affected_versions' => '<5.4.20,>=6.0.0 <6.0.20,>=6.1.0 <6.1.12,>=6.2.0 <6.2.6',
                    'severity'          => 'high',
                ],
            ],
            'guzzlehttp/guzzle' => [
                [
                    'cve'               => 'CVE-2022-31090',
                    'title'             => 'CURLOPT_HTTPAUTH leak',
                    'affected_versions' => '<6.5.8,>=7.0.0 <7.4.5',
                    'severity'          => 'high',
                ],
            ],
        ];
    }

    /**
     * Check if a package version is vulnerable.
     *
     * @param  array<string, array<array<string, mixed>>>  $advisories
     *
     * @return array<array<string, mixed>>
     */
    protected function checkPackageVulnerabilities(string $name, string $version, array $advisories): array
    {
        $vulnerabilities = [];

        if (! isset($advisories[$name])) {
            return $vulnerabilities;
        }

        foreach ($advisories[$name] as $advisory) {
            if ($this->versionMatchesConstraint($version, $advisory['affected_versions'] ?? '')) {
                $vulnerabilities[] = [
                    'id'          => $advisory['cve'] ?? 'UNKNOWN',
                    'title'       => "Vulnerable Package: {$name}",
                    'description' => $advisory['title'] ?? 'Known vulnerability in package',
                    'severity'    => $advisory['severity'] ?? 'medium',
                    'category'    => 'A06:2021-Vulnerable and Outdated Components',
                    'location'    => "{$name}@{$version}",
                    'remediation' => 'Update to a patched version',
                ];
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check NPM package for known vulnerabilities.
     *
     * @return array<array<string, mixed>>
     */
    protected function checkNpmVulnerabilities(string $name, string $version): array
    {
        // Known vulnerable NPM packages (subset for demonstration)
        $knownVulnerabilities = [
            'lodash' => [
                [
                    'cve'      => 'CVE-2021-23337',
                    'affected' => '<4.17.21',
                    'severity' => 'high',
                    'title'    => 'Command Injection',
                ],
            ],
            'axios' => [
                [
                    'cve'      => 'CVE-2021-3749',
                    'affected' => '<0.21.2',
                    'severity' => 'high',
                    'title'    => 'Server-Side Request Forgery',
                ],
            ],
        ];

        $vulnerabilities = [];

        if (isset($knownVulnerabilities[$name])) {
            foreach ($knownVulnerabilities[$name] as $vuln) {
                if ($this->versionMatchesConstraint($version, $vuln['affected'])) {
                    $vulnerabilities[] = [
                        'id'          => $vuln['cve'],
                        'title'       => "Vulnerable NPM Package: {$name}",
                        'description' => $vuln['title'],
                        'severity'    => $vuln['severity'],
                        'category'    => 'A06:2021-Vulnerable and Outdated Components',
                        'location'    => "{$name}@{$version} (npm)",
                        'remediation' => 'Update to a patched version',
                    ];
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check for outdated packages.
     *
     * @param  array<array<string, mixed>>  $packages
     */
    protected function checkOutdatedPackages(array $packages): void
    {
        foreach ($packages as $package) {
            $name    = $package['name'] ?? '';
            $version = $package['version'] ?? '';
            $time    = $package['time'] ?? null;

            if ($time) {
                $packageDate = strtotime($time);
                $twoYearsAgo = strtotime('-2 years');

                if ($packageDate && $packageDate < $twoYearsAgo) {
                    $this->findings[] = SecurityFinding::low(
                        'Outdated Package',
                        "Package '{$name}' version {$version} is over 2 years old",
                        'A06:2021-Vulnerable and Outdated Components',
                        $this->composerLockPath,
                        'Consider updating to a newer version',
                    );
                }
            }
        }
    }

    /**
     * Check if a version matches a constraint using Composer's Semver library.
     */
    protected function versionMatchesConstraint(string $version, string $constraint): bool
    {
        // Normalize version
        $version = ltrim($version, 'v');

        // Handle empty constraint
        if (empty($constraint)) {
            return false;
        }

        try {
            return Semver::satisfies($version, $constraint);
        } catch (Exception $e) {
            // Fallback to simple comparison for malformed constraints
            return $this->fallbackVersionCheck($version, $constraint);
        }
    }

    /**
     * Fallback version check for when Semver fails.
     */
    protected function fallbackVersionCheck(string $version, string $constraint): bool
    {
        // Simple constraint parsing as fallback
        $constraints = explode(',', $constraint);

        foreach ($constraints as $c) {
            $c = trim($c);

            if (str_starts_with($c, '<')) {
                $targetVersion = ltrim($c, '<>=');
                if (version_compare($version, $targetVersion, '<')) {
                    return true;
                }
            }
        }

        return false;
    }
}
