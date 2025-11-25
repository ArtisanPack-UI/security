<?php

namespace ArtisanPackUI\Security;

use Laminas\Escaper\Escaper;
use function ArtisanPackUI\Security\HTMLawed\htmLawed;

class Security
{
	/**
	 * Returns a sanitized email string.
	 *
	 * @param string|null $email The email to sanitize.
	 * @return string
	 * @since 1.0.0
	 */
	public function sanitizeEmail( string|null $email = '' ): string
	{
		if ( $email === null || $email === '' ) {
			return '';
		}

		return filter_var( $email, FILTER_SANITIZE_EMAIL );
	}

	/**
	 * Returns a sanitized url string.
	 *
	 * @param string|null $url The url to sanitize.
	 * @return string
	 * @since 1.0.0
	 */
	public function sanitizeUrl( string|null $url = '' ): string
	{
		if ( $url === null || $url === '' ) {
			return '';
		}
		return filter_var( $url, FILTER_SANITIZE_URL );
	}

	/**
	 * Returns a sanitized filename.
	 *
	 * @param string|null $filename The filename to sanitize.
	 * @return string
	 * @since 1.0.0
	 */
	public function sanitizeFilename( string|null $filename = '' ): string
	{
		if ( $filename === null || $filename === '' ) {
			return '';
		}
		return htmlspecialchars( $filename, ENT_QUOTES, 'UTF-8' );
	}

	/**
	 * Returns a sanitized password.
	 *
	 * @param string|null $password The password to sanitize.
	 * @return string
	 * @since 1.0.0
	 */
	public function sanitizePassword( string|null $password = '' ): string
	{
		if ( $password === null || $password === '' ) {
			return '';
		}
		return htmlspecialchars( $password, ENT_QUOTES, 'UTF-8' );
	}

	/**
	 * Returns a sanitized integer.
	 *
	 * @param mixed $integer The integer to sanitize.
	 * @return int
	 * @since 1.0.0
	 */
	public function sanitizeInt( mixed $integer = '' ): int
	{
		return intval( $integer );
	}

	/**
	 * Returns a sanitized date string.
	 *
	 * @param string|null $date The date to sanitize.
	 * @return string
	 * @since 1.0.0
	 */
	public function sanitizeDate( string|null $date = '' ): string
	{
		if ( $date === null || $date === '' ) {
			return '';
		}
		return date( 'Y-m-d', strtotime( $date ) );
	}

	/**
	 * Returns a sanitized datetime string.
	 *
	 * @param string $datetime The datetime to sanitize.
	 * @return string
	 * @since 1.0.0
	 */
	public function sanitizeDatetime( string $datetime = '' ): string
	{
		return date( 'Y-m-d H:i:s', strtotime( $datetime ) );
	}

	/**
	 * Returns a sanitized float value.
	 *
	 * @param float $float    The number to sanitize.
	 * @param int   $decimals The number of decimal places to round to.
	 * @return float
	 * @since 1.0.0
	 */
	public function sanitizeFloat( float $float, int $decimals = 2 ): float
	{
		return number_format( $float, $decimals, '.', '' );
	}

	/**
	 * Returns a sanitized array.
	 *
	 * @param array $options The array to sanitize.
	 * @return array
	 * @since 1.0.0
	 */
	public function sanitizeArray( array $options = [] ): array
	{

		return array_map( function ( $value ) {
			return $this->sanitizeText( $value );
		}, $options );
	}

	/**
	 * Returns a sanitized version of the string.
	 *
	 * @param string|null $input The string to sanitize.
	 * @return string
	 * @since 1.0.0
	 */
	public function sanitizeText( string|null $input = '' ): string
	{
		if ( $input === null || $input === '' ) {
			return '';
		}
		return strip_tags( $input );
	}

	/**
	 * Returns an escaped string of HTML.
	 *
	 * @param string|null $string The string to escape.
	 * @return string
	 * @since 1.0.0
	 */
	public function escHtml( string|null $string = '' ): string
	{
		if ( $string === null || $string === '' ) {
			return '';
		}
		return ( new Escaper() )->escapeHtml( $string );
	}

	/**
	 * Returns an escaped string of HTML attributes.
	 *
	 * @param string|null $string The string to escape.
	 * @return string
	 * @since 1.0.0
	 */
	public function escAttr( string|null $string = '' ): string
	{
		if ( $string === null || $string === '' ) {
			return '';
		}

		return ( new Escaper() )->escapeHtmlAttr( $string );
	}

	/**
	 * Returns an escaped URL string.
	 *
	 * @param string|null $string The url to escape.
	 * @return string
	 * @since 1.0.0
	 */
	public function escUrl( string|null $string = '' ): string
	{
		if ( $string === null || $string === '' ) {
			return '';
		}
		return ( new Escaper() )->escapeUrl( $string );
	}

	/**
	 * Returns an escaped JavaScript string.
	 *
	 * @param string|null $string The JavaScript to escape.
	 * @return string
	 * @since 1.0.0
	 */
	public function escJs( string|null $string = '' ): string
	{
		if ( $string === null || $string === '' ) {
			return '';
		}
		return ( new Escaper() )->escapeJs( $string );
	}

	/**
	 * Returns an escaped CSS string.
	 *
	 * @param string|null $string The CSS to escape.
	 * @return string
	 * @since 1.0.0
	 */
	public function escCss( string|null $string = '' ): string
	{
		if ( $string === null || $string === '' ) {
			return '';
		}
		return ( new Escaper() )->escapeCss( $string );
	}

	/**
	 * Returns a secure string for content containing HTML markup.
	 *
	 * @param string $html   The HTML to clean.
	 * @param mixed  $config Configuration options.
	 * @param mixed  $spec   Specification options.
	 * @return string
	 * @since 1.0.0
	 */
	public function kses( string $html, mixed $config = 1, mixed $spec = array() ): string
	{
		return htmLawed( $html, $config, $spec );
	}
}
