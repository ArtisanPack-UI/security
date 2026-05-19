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
        if (! Schema::hasTable('csp_violation_reports')) {
            Schema::create('csp_violation_reports', function (Blueprint $table): void {
                $table->id();
                $table->string('document_uri', 2048);
                $table->string('blocked_uri', 2048)->nullable();
                $table->string('violated_directive')->index();
                $table->string('effective_directive')->nullable();
                $table->text('original_policy')->nullable();
                $table->string('disposition', 20)->default('enforce')->index();
                $table->string('referrer', 2048)->nullable();
                $table->text('script_sample')->nullable();
                $table->string('source_file', 2048)->nullable();
                $table->unsignedInteger('line_number')->nullable();
                $table->unsignedInteger('column_number')->nullable();
                $table->string('status_code', 10)->nullable();
                $table->text('user_agent')->nullable();
                $table->string('ip_address', 45)->nullable()->index();
                $table->string('fingerprint', 64)->unique();
                $table->unsignedInteger('occurrence_count')->default(1);
                $table->timestamp('first_seen_at')->index();
                $table->timestamp('last_seen_at')->index();
                $table->timestamps();

                $table->index(['violated_directive', 'last_seen_at']);
                $table->index(['disposition', 'last_seen_at']);
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('csp_violation_reports');
    }
};
