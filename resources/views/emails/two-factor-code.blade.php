@component('mail::message')
	# {{ __('Your Two-Factor Authentication Code') }}

	{{ __('Here is your one-time code to complete your login.') }}

	@component('mail::panel')
		{{ $code }}
	@endcomponent

	{{ __('This code will expire in 10 minutes.') }}

	{{ __('If you did not request this login code, you can safely ignore this email or contact support if you believe your account has been compromised.') }}

	{{ __('Thanks,') }}<br>
	{{ config('app.name') }}
@endcomponent