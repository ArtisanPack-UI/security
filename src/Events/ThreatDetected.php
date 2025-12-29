<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\ThreatIndicator;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Broadcasting\PrivateChannel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ThreatDetected implements ShouldBroadcast
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * Create a new event instance.
     *
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public string $threatType,
        public string $indicator,
        public string $indicatorType,
        public int $confidence,
        public string $severity,
        public array $context = [],
        public ?ThreatIndicator $threatIndicator = null
    ) {
    }

    /**
     * Get the channels the event should broadcast on.
     *
     * @return array<int, \Illuminate\Broadcasting\Channel>
     */
    public function broadcastOn(): array
    {
        return [
            new PrivateChannel('security.dashboard'),
            new PrivateChannel('security.threats'),
        ];
    }

    /**
     * Get the data to broadcast.
     *
     * @return array<string, mixed>
     */
    public function broadcastWith(): array
    {
        return [
            'threat_type' => $this->threatType,
            'indicator' => $this->indicator,
            'indicator_type' => $this->indicatorType,
            'confidence' => $this->confidence,
            'severity' => $this->severity,
            'context' => $this->context,
            'detected_at' => now()->toIso8601String(),
        ];
    }

    /**
     * The event's broadcast name.
     */
    public function broadcastAs(): string
    {
        return 'threat.detected';
    }

    /**
     * Create an event from threat intelligence check result.
     *
     * @param  array<string, mixed>  $result
     * @param  array<string, mixed>  $context
     */
    public static function fromThreatCheck(array $result, array $context = []): ?self
    {
        if (! ($result['is_malicious'] ?? false)) {
            return null;
        }

        $severity = match (true) {
            ($result['confidence'] ?? 0) >= 80 => 'critical',
            ($result['confidence'] ?? 0) >= 60 => 'high',
            ($result['confidence'] ?? 0) >= 40 => 'medium',
            default => 'low',
        };

        return new self(
            threatType: $result['threat_types'][0] ?? 'unknown',
            indicator: $result['indicator'] ?? '',
            indicatorType: $result['indicator_type'] ?? 'unknown',
            confidence: $result['confidence'] ?? 0,
            severity: $severity,
            context: $context
        );
    }
}
