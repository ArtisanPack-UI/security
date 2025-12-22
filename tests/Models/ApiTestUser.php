<?php

namespace Tests\Models;

use ArtisanPackUI\Security\Concerns\HasApiTokens;
use ArtisanPackUI\Security\Concerns\HasRoles;
use Illuminate\Foundation\Auth\User;

class ApiTestUser extends User
{
    use HasRoles;
    use HasApiTokens;

    protected $table = 'users';

    protected $fillable = [
        'id',
        'name',
        'email',
    ];
}
