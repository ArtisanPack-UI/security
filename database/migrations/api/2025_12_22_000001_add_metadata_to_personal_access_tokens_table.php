<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (Schema::hasTable('personal_access_tokens')) {
            Schema::table('personal_access_tokens', function (Blueprint $table): void {
                if (! Schema::hasColumn('personal_access_tokens', 'expires_at')) {
                    $table->timestamp('expires_at')->nullable()->after('last_used_at');
                }
                if (! Schema::hasColumn('personal_access_tokens', 'ip_address')) {
                    $table->string('ip_address', 45)->nullable()->after('expires_at');
                }
                if (! Schema::hasColumn('personal_access_tokens', 'user_agent')) {
                    $table->text('user_agent')->nullable()->after('ip_address');
                }
                if (! Schema::hasColumn('personal_access_tokens', 'metadata')) {
                    $table->json('metadata')->nullable()->after('user_agent');
                }
                if (! Schema::hasColumn('personal_access_tokens', 'is_revoked')) {
                    $table->boolean('is_revoked')->default(false)->after('metadata');
                }
                if (! Schema::hasColumn('personal_access_tokens', 'revoked_at')) {
                    $table->timestamp('revoked_at')->nullable()->after('is_revoked');
                }
            });

            // Add indexes separately to avoid issues with existing indexes
            // Using Laravel's native Schema::hasIndex() for compatibility with Laravel 10.24+ and 11
            if (! Schema::hasIndex('personal_access_tokens', 'personal_access_tokens_expires_at_index')) {
                Schema::table('personal_access_tokens', function (Blueprint $table): void {
                    $table->index('expires_at');
                });
            }
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (Schema::hasTable('personal_access_tokens')) {
            Schema::table('personal_access_tokens', function (Blueprint $table): void {
                $columns = ['expires_at', 'ip_address', 'user_agent', 'metadata', 'is_revoked', 'revoked_at'];

                foreach ($columns as $column) {
                    if (Schema::hasColumn('personal_access_tokens', $column)) {
                        $table->dropColumn($column);
                    }
                }
            });
        }
    }
};
