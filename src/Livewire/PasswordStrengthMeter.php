<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Livewire;

use ArtisanPackUI\Security\Contracts\PasswordSecurityServiceInterface;
use Livewire\Attributes\Reactive;
use Livewire\Component;

class PasswordStrengthMeter extends Component
{
    /**
     * The password to evaluate.
     */
    #[Reactive]
    public string $password = '';

    /**
     * Additional user inputs to penalize in strength calculation.
     *
     * @var array<int, string>
     */
    public array $userInputs = [];

    /**
     * The calculated strength score (0-4).
     */
    public int $score = 0;

    /**
     * The strength label.
     */
    public string $label = '';

    /**
     * The estimated crack time.
     */
    public string $crackTime = '';

    /**
     * Feedback suggestions for improving the password.
     *
     * @var array<int, string>
     */
    public array $feedback = [];

    /**
     * Password requirements and their met status.
     *
     * @var array<string, array<string, mixed>>
     */
    public array $requirements = [];

    /**
     * Mount the component.
     *
     * @param  array<int, string>  $userInputs
     */
    public function mount(array $userInputs = []): void
    {
        $this->userInputs = $userInputs;
        $this->initializeRequirements();
    }

    /**
     * Handle password updates.
     */
    public function updatedPassword(): void
    {
        if (empty($this->password)) {
            $this->resetMetrics();

            return;
        }

        $service = app(PasswordSecurityServiceInterface::class);
        $result = $service->calculateStrength($this->password, $this->userInputs);

        $this->score = $result['score'];
        $this->label = $result['label'];
        $this->crackTime = $result['crackTime'] ?? '';
        $this->feedback = $result['feedback'] ?? [];

        // Update requirements status
        $this->updateRequirements();
    }

    /**
     * Get the badge color based on the score.
     */
    public function getBadgeColor(): string
    {
        return match ($this->score) {
            0 => 'error',
            1 => 'error',
            2 => 'warning',
            3 => 'info',
            4 => 'success',
            default => 'secondary',
        };
    }

    /**
     * Get the progress bar color based on the score.
     */
    public function getProgressColor(): string
    {
        return match ($this->score) {
            0 => 'error',
            1 => 'error',
            2 => 'warning',
            3 => 'info',
            4 => 'success',
            default => 'secondary',
        };
    }

    /**
     * Get the progress bar width based on the score.
     */
    public function getBarWidth(): int
    {
        return match ($this->score) {
            0 => 5,
            1 => 25,
            2 => 50,
            3 => 75,
            4 => 100,
            default => 0,
        };
    }

    /**
     * Render the component.
     *
     * @return \Illuminate\Contracts\View\View
     */
    public function render()
    {
        return view('security::livewire.password-strength-meter');
    }

    /**
     * Initialize the requirements checklist.
     */
    protected function initializeRequirements(): void
    {
        $config = config('artisanpack.security.passwordSecurity.complexity', []);

        $this->requirements = [
            'length' => [
                'label' => sprintf('At least %d characters', $config['minLength'] ?? 8),
                'met' => false,
                'enabled' => true,
            ],
            'uppercase' => [
                'label' => 'Contains uppercase letter',
                'met' => false,
                'enabled' => $config['requireUppercase'] ?? true,
            ],
            'lowercase' => [
                'label' => 'Contains lowercase letter',
                'met' => false,
                'enabled' => $config['requireLowercase'] ?? true,
            ],
            'number' => [
                'label' => 'Contains number',
                'met' => false,
                'enabled' => $config['requireNumbers'] ?? true,
            ],
            'symbol' => [
                'label' => 'Contains special character',
                'met' => false,
                'enabled' => $config['requireSymbols'] ?? true,
            ],
        ];
    }

    /**
     * Update the requirements based on the current password.
     */
    protected function updateRequirements(): void
    {
        $config = config('artisanpack.security.passwordSecurity.complexity', []);

        $this->requirements['length']['met'] = strlen($this->password) >= ($config['minLength'] ?? 8);
        $this->requirements['uppercase']['met'] = (bool) preg_match('/[A-Z]/', $this->password);
        $this->requirements['lowercase']['met'] = (bool) preg_match('/[a-z]/', $this->password);
        $this->requirements['number']['met'] = (bool) preg_match('/[0-9]/', $this->password);
        $this->requirements['symbol']['met'] = (bool) preg_match('/[^A-Za-z0-9]/', $this->password);
    }

    /**
     * Reset all metrics to their initial state.
     */
    protected function resetMetrics(): void
    {
        $this->score = 0;
        $this->label = '';
        $this->crackTime = '';
        $this->feedback = [];
        $this->initializeRequirements();
    }
}
