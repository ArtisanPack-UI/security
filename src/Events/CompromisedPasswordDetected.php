<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class CompromisedPasswordDetected
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * The user who attempted to use a compromised password.
     */
    public ?Authenticatable $user;

    /**
     * The number of times the password has been seen in breaches.
     */
    public int $occurrences;

    /**
     * The context in which the compromised password was detected.
     */
    public string $context;

    /**
     * Create a new event instance.
     *
     * @param  string  $context  The context (e.g., 'registration', 'password_change', 'login')
     */
    public function __construct(?Authenticatable $user, int $occurrences, string $context = 'unknown')
    {
        $this->user = $user;
        $this->occurrences = $occurrences;
        $this->context = $context;
    }
}
