<?php
/**
 * Two-Factor Code Mailable
 *
 * Defines the email sent to users containing their two-factor authentication code.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\Mail
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

/**
 * Defines the 2FA code email.
 *
 * @since 1.2.0
 */
class TwoFactorCodeMailable extends Mailable
{
	use SerializesModels;

	/**
	 * The two-factor authentication code.
	 *
	 * @since 1.2.0
	 * @var int
	 */
	protected int $code;

	/**
	 * Create a new message instance.
	 *
	 * @since 1.2.0
	 *
	 * @param int $code The 2FA code.
	 */
	public function __construct( int $code )
	{
		$this->code = $code;
	}

	/**
	 * Get the message envelope.
	 *
	 * @since 1.2.0
	 *
	 * @return Envelope
	 */
	public function envelope(): Envelope
	{
		return new Envelope(
			subject: 'Your Two-Factor Authentication Code',
		);
	}

	/**
	 * Get the message content definition.
	 *
	 * @since 1.2.0
	 *
	 * @return Content
	 */
	public function content(): Content
	{
		return new Content(
			markdown: 'artisanpack-ui-security::emails.two-factor-code',
			with:     [
						  'code' => $this->code,
					  ]
		);
	}
}