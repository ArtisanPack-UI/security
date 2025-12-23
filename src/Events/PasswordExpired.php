<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Carbon;

class PasswordExpired
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * The user whose password has expired.
     */
    public Authenticatable $user;

    /**
     * The timestamp when the password expired.
     */
    public Carbon $expiredAt;

    /**
     * Create a new event instance.
     */
    public function __construct(Authenticatable $user, ?Carbon $expiredAt = null)
    {
        $this->user = $user;
        $this->expiredAt = $expiredAt ?? now();
    }
}
