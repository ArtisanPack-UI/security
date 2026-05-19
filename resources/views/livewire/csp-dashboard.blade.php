<div>
    <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold">CSP Violation Dashboard</h1>
        <select wire:model.live="days" class="select select-bordered">
            <option value="1">Last 24 hours</option>
            <option value="7">Last 7 days</option>
            <option value="14">Last 14 days</option>
            <option value="30">Last 30 days</option>
        </select>
    </div>

    {{-- Statistics Cards --}}
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <x-artisanpack-stat
            title="Total Violations"
            :value="number_format($totalViolations)"
            icon="heroicon-o-shield-exclamation"
            color="text-error"
        />
        <x-artisanpack-stat
            title="Unique Violations"
            :value="number_format($uniqueViolations)"
            icon="heroicon-o-finger-print"
            color="text-warning"
        />
        <x-artisanpack-stat
            title="Enforced"
            :value="number_format($enforcedCount)"
            icon="heroicon-o-x-circle"
            color="text-error"
        />
        <x-artisanpack-stat
            title="Report Only"
            :value="number_format($reportOnlyCount)"
            icon="heroicon-o-document-text"
            color="text-info"
        />
    </div>

    {{-- Charts --}}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Violations by Directive</h3>
            </x-slot:header>
            @if(count($violationsByDirectiveChart) > 0)
                <x-artisanpack-chart wire:model="violationsByDirectiveChart" class="h-64" />
            @else
                <div class="flex items-center justify-center h-64 text-gray-500">
                    No violation data available.
                </div>
            @endif
        </x-artisanpack-card>

        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Violation Trend</h3>
            </x-slot:header>
            @if(count($violationTrendChart) > 0)
                <x-artisanpack-chart wire:model="violationTrendChart" class="h-64" />
            @else
                <div class="flex items-center justify-center h-64 text-gray-500">
                    No trend data available.
                </div>
            @endif
        </x-artisanpack-card>
    </div>

    {{-- Top Blocked URIs and Recent Violations --}}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Top Blocked URIs</h3>
            </x-slot:header>
            @forelse($topBlockedUris as $item)
                <div class="flex items-center justify-between p-2 border-b last:border-b-0">
                    <span class="text-sm truncate flex-1" title="{{ $item['full_uri'] }}">
                        {{ $item['uri'] }}
                    </span>
                    <span class="badge badge-error ml-2">{{ number_format($item['count']) }}</span>
                </div>
            @empty
                <p class="text-gray-500 p-4">No blocked URIs recorded.</p>
            @endforelse
        </x-artisanpack-card>

        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Recent Violations</h3>
            </x-slot:header>
            @forelse($recentViolations as $violation)
                <div class="flex items-center gap-4 p-2 border-b last:border-b-0">
                    <x-artisanpack-icon name="heroicon-o-shield-exclamation" class="w-5 h-5 text-error flex-shrink-0" />
                    <div class="flex-1 min-w-0">
                        <div class="font-medium truncate">{{ $violation['directive'] }}</div>
                        <div class="text-sm text-gray-500 truncate">{{ $violation['blocked_uri'] }}</div>
                    </div>
                    <div class="text-right flex-shrink-0">
                        <span class="badge badge-ghost">{{ $violation['occurrence_count'] }}x</span>
                        <div class="text-xs text-gray-500">{{ $violation['last_seen'] }}</div>
                    </div>
                </div>
            @empty
                <p class="text-gray-500 p-4">No violations recorded.</p>
            @endforelse
        </x-artisanpack-card>
    </div>

    {{-- CSP Configuration Info --}}
    <x-artisanpack-card class="mt-6">
        <x-slot:header>
            <h3 class="text-lg font-bold">Current Configuration</h3>
        </x-slot:header>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 p-2">
            <div>
                <span class="text-gray-500">CSP Enabled:</span>
                <span class="font-medium {{ config('artisanpack.security.csp.enabled', true) ? 'text-success' : 'text-error' }}">
                    {{ config('artisanpack.security.csp.enabled', true) ? 'Yes' : 'No' }}
                </span>
            </div>
            <div>
                <span class="text-gray-500">Mode:</span>
                <span class="font-medium {{ config('artisanpack.security.csp.reportOnly', false) ? 'text-warning' : 'text-success' }}">
                    {{ config('artisanpack.security.csp.reportOnly', false) ? 'Report Only' : 'Enforcing' }}
                </span>
            </div>
            <div>
                <span class="text-gray-500">Preset:</span>
                <span class="font-medium">{{ ucfirst(config('artisanpack.security.csp.preset', 'livewire')) }}</span>
            </div>
        </div>
    </x-artisanpack-card>
</div>
