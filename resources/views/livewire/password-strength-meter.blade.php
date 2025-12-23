<div class="password-strength-meter">
    {{-- Strength Bar --}}
    <div class="mt-2">
        <div class="flex justify-between mb-1">
            <x-artisanpack-text size="text-sm" semibold>
                Password Strength
            </x-artisanpack-text>
            @if($label)
                <x-artisanpack-badge
                    :value="$label"
                    :color="$this->getBadgeColor()"
                    class="badge-sm"
                />
            @endif
        </div>
        <x-artisanpack-progress
            :value="$this->getBarWidth()"
            :class="'progress-' . $this->getProgressColor()"
        />
    </div>

    {{-- Crack Time --}}
    @if(config('artisanpack.security.passwordSecurity.strengthMeter.showCrackTime') && $crackTime)
        <x-artisanpack-text size="text-xs" muted class="mt-1">
            Estimated crack time: <span class="font-medium">{{ $crackTime }}</span>
        </x-artisanpack-text>
    @endif

    {{-- Requirements Checklist --}}
    <div class="mt-3 space-y-1">
        @foreach($requirements as $key => $requirement)
            @if($requirement['enabled'] ?? true)
                <div class="flex items-center">
                    @if($requirement['met'])
                        <x-artisanpack-icon name="o-check-circle" class="w-4 h-4 text-success mr-2" />
                        <x-artisanpack-text size="text-sm" class="text-success">
                            {{ $requirement['label'] }}
                        </x-artisanpack-text>
                    @else
                        <x-artisanpack-icon name="o-x-circle" class="w-4 h-4 text-gray-400 mr-2" />
                        <x-artisanpack-text size="text-sm" muted>
                            {{ $requirement['label'] }}
                        </x-artisanpack-text>
                    @endif
                </div>
            @endif
        @endforeach
    </div>

    {{-- Feedback Messages --}}
    @if(config('artisanpack.security.passwordSecurity.strengthMeter.showFeedback') && count($feedback) > 0)
        <x-artisanpack-alert
            title="Suggestions"
            icon="o-light-bulb"
            color="warning"
            class="mt-3"
        >
            <ul class="mt-1 text-sm list-disc list-inside">
                @foreach($feedback as $suggestion)
                    <li>{{ $suggestion }}</li>
                @endforeach
            </ul>
        </x-artisanpack-alert>
    @endif
</div>
