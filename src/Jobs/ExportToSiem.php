<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Jobs;

use ArtisanPackUI\Security\Analytics\Siem\SiemExportService;
use ArtisanPackUI\Security\Models\Anomaly;
use ArtisanPackUI\Security\Models\SecurityIncident;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class ExportToSiem implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     *
     * @var int
     */
    public int $tries = 3;

    /**
     * The number of seconds the job can run before timing out.
     *
     * @var int
     */
    public int $timeout = 60;

    /**
     * The number of seconds to wait before retrying the job.
     *
     * @var int
     */
    public int $backoff = 30;

    /**
     * Create a new job instance.
     *
     * @param  array<string, mixed>|null  $event
     */
    public function __construct(
        protected ?array $event = null,
        protected ?int $anomalyId = null,
        protected ?int $incidentId = null,
        protected bool $flushBuffer = false
    ) {
    }

    /**
     * Execute the job.
     */
    public function handle(SiemExportService $siemExport): void
    {
        if (! $siemExport->isEnabled()) {
            \Log::debug('SIEM export is disabled, skipping job');

            return;
        }

        // Export specific event
        if ($this->event !== null) {
            $siemExport->exportEvent($this->event);
        }

        // Export anomaly
        if ($this->anomalyId !== null) {
            $anomaly = Anomaly::find($this->anomalyId);
            if ($anomaly) {
                $siemExport->exportAnomaly($anomaly);
            }
        }

        // Export incident
        if ($this->incidentId !== null) {
            $incident = SecurityIncident::find($this->incidentId);
            if ($incident) {
                $siemExport->exportIncident($incident);
            }
        }

        // Flush buffer if requested
        if ($this->flushBuffer) {
            $siemExport->flush();
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        \Log::error('Failed to export to SIEM', [
            'exception' => $exception->getMessage(),
            'anomaly_id' => $this->anomalyId,
            'incident_id' => $this->incidentId,
            'has_event' => $this->event !== null,
        ]);
    }

    /**
     * Get the tags that should be assigned to the job.
     *
     * @return array<int, string>
     */
    public function tags(): array
    {
        $tags = ['security', 'siem-export'];

        if ($this->anomalyId) {
            $tags[] = "anomaly:{$this->anomalyId}";
        }

        if ($this->incidentId) {
            $tags[] = "incident:{$this->incidentId}";
        }

        return $tags;
    }

    /**
     * Create a job to export an anomaly.
     */
    public static function forAnomaly(Anomaly $anomaly): self
    {
        return new self(anomalyId: $anomaly->id);
    }

    /**
     * Create a job to export an incident.
     */
    public static function forIncident(SecurityIncident $incident): self
    {
        return new self(incidentId: $incident->id);
    }

    /**
     * Create a job to flush the SIEM buffer.
     */
    public static function flush(): self
    {
        return new self(flushBuffer: true);
    }
}
