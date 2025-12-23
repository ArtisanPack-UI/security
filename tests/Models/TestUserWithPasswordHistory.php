<?php

namespace Tests\Models;

use ArtisanPackUI\Security\Concerns\HasPasswordHistory;
use ArtisanPackUI\Security\Concerns\HasRoles;
use Illuminate\Foundation\Auth\User;

class TestUserWithPasswordHistory extends User
{
    use HasRoles;
    use HasPasswordHistory;

    protected $table = 'users';

    protected $fillable = [
        'id',
        'name',
        'email',
        'password',
        'password_changed_at',
        'password_expires_at',
        'force_password_change',
        'grace_logins_remaining',
    ];

    protected $casts = [
        'password_changed_at' => 'datetime',
        'password_expires_at' => 'datetime',
        'force_password_change' => 'boolean',
    ];
}
