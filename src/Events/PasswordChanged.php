<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Carbon;

class PasswordChanged
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * The user whose password was changed.
     */
    public Authenticatable $user;

    /**
     * The timestamp when the password was changed.
     */
    public Carbon $changedAt;

    /**
     * Create a new event instance.
     */
    public function __construct(Authenticatable $user, ?Carbon $changedAt = null)
    {
        $this->user = $user;
        $this->changedAt = $changedAt ?? now();
    }
}
