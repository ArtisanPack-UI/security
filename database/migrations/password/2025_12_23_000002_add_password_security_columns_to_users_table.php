<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Add password security columns to users table.
 *
 * Note: This migration only runs if the `users` table exists. Applications
 * without a standard users table can skip this migration or customize it
 * for their user model's table.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Only modify users table if it exists
        if (! Schema::hasTable('users')) {
            return;
        }

        Schema::table('users', function (Blueprint $table): void {
            if (! Schema::hasColumn('users', 'password_changed_at')) {
                $table->timestamp('password_changed_at')
                    ->nullable()
                    ->after('password');
            }

            if (! Schema::hasColumn('users', 'password_expires_at')) {
                $table->timestamp('password_expires_at')
                    ->nullable()
                    ->after('password_changed_at');
            }

            if (! Schema::hasColumn('users', 'force_password_change')) {
                $table->boolean('force_password_change')
                    ->default(false)
                    ->after('password_expires_at');
            }

            if (! Schema::hasColumn('users', 'grace_logins_remaining')) {
                $table->unsignedTinyInteger('grace_logins_remaining')
                    ->nullable()
                    ->after('force_password_change');
            }
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('users')) {
            return;
        }

        Schema::table('users', function (Blueprint $table): void {
            $columns = ['password_changed_at', 'password_expires_at', 'force_password_change', 'grace_logins_remaining'];

            foreach ($columns as $column) {
                if (Schema::hasColumn('users', $column)) {
                    $table->dropColumn($column);
                }
            }
        });
    }
};
