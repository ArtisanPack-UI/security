<?php

declare(strict_types=1);

namespace Tests\Unit;

use ArtisanPackUI\Security\Services\Csp\CspPolicyBuilder;
use ArtisanPackUI\Security\Services\Csp\Presets\LivewirePreset;
use ArtisanPackUI\Security\Services\Csp\Presets\RelaxedPreset;
use ArtisanPackUI\Security\Services\Csp\Presets\StrictPreset;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class CspPresetsTest extends TestCase
{
    private string $testNonce = 'dGVzdC1ub25jZS0xMjM0NTY3ODk=';

    #[Test]
    public function livewire_preset_uses_strict_dynamic(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new LivewirePreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString("'strict-dynamic'", $policy);
    }

    #[Test]
    public function livewire_preset_includes_nonce(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new LivewirePreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString("'nonce-{$this->testNonce}'", $policy);
    }

    #[Test]
    public function livewire_preset_blocks_objects(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new LivewirePreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString("object-src 'none'", $policy);
    }

    #[Test]
    public function strict_preset_blocks_by_default(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new StrictPreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString("default-src 'none'", $policy);
    }

    #[Test]
    public function strict_preset_blocks_objects(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new StrictPreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString("object-src 'none'", $policy);
    }

    #[Test]
    public function strict_preset_requires_nonce_for_scripts(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new StrictPreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString("'nonce-{$this->testNonce}'", $policy);
    }

    #[Test]
    public function relaxed_preset_allows_self(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new RelaxedPreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString("default-src 'self'", $policy);
    }

    #[Test]
    public function relaxed_preset_uses_strict_dynamic(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new RelaxedPreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        // Relaxed preset uses strict-dynamic instead of unsafe-inline for better security
        $this->assertStringContainsString("'strict-dynamic'", $policy);
    }

    #[Test]
    public function relaxed_preset_allows_https(): void
    {
        $builder = new CspPolicyBuilder;
        $preset  = new RelaxedPreset;

        $preset->apply($builder, $this->testNonce);
        $policy = $builder->build();

        $this->assertStringContainsString('https:', $policy);
    }

    #[Test]
    public function presets_can_return_their_name(): void
    {
        $livewire = new LivewirePreset;
        $strict   = new StrictPreset;
        $relaxed  = new RelaxedPreset;

        $this->assertEquals('livewire', $livewire->getName());
        $this->assertEquals('strict', $strict->getName());
        $this->assertEquals('relaxed', $relaxed->getName());
    }

    #[Test]
    public function presets_can_return_their_description(): void
    {
        $livewire = new LivewirePreset;
        $strict   = new StrictPreset;
        $relaxed  = new RelaxedPreset;

        $this->assertNotEmpty($livewire->getDescription());
        $this->assertNotEmpty($strict->getDescription());
        $this->assertNotEmpty($relaxed->getDescription());
    }
}
