<?php

use ArtisanPackUI\Security\Security;

if ( !function_exists( 'security' ) ) {
	/**
	 * Get the Security instance.
	 *
	 * @return Security
	 */
	function security()
	{
		return app( 'security' );
	}
}

if ( !function_exists( 'sanitizeEmail' ) ) {
	function sanitizeEmail( string|null $email = '' ): string
	{
		return security()->sanitizeEmail( $email );
	}
}

if ( !function_exists( 'sanitizeUrl' ) ) {
	function sanitizeUrl( string|null $url = '' ): string
	{
		return security()->sanitizeUrl( $url );
	}
}

if ( !function_exists( 'sanitizeFilename' ) ) {
	function sanitizeFilename( string|null $filename = '' ): string
	{
		return security()->sanitizeFilename( $filename );
	}
}

if ( !function_exists( 'sanitizePassword' ) ) {
	function sanitizePassword( string|null $password = '' ): string
	{
		return security()->sanitizePassword( $password );
	}
}

if ( !function_exists( 'sanitizeInt' ) ) {
	function sanitizeInt( mixed $int = '' ): int
	{
		return security()->sanitizeInt( $int );
	}
}

if ( !function_exists( 'sanitizeDate' ) ) {
	function sanitizeDate( string|null $date = '' ): string
	{
		return security()->sanitizeDate( $date );
	}
}

if ( !function_exists( 'sanitizeDatetime' ) ) {
	function sanitizeDatetime( string|null $datetime = '' ): string
	{
		return security()->sanitizeDatetime( $datetime );
	}
}

if ( !function_exists( 'sanitizeFloat' ) ) {
	function sanitizeFloat( mixed $float = '' ): int
	{
		return security()->sanitizeFloat( $float );
	}
}

if ( !function_exists( 'sanitizeArray' ) ) {
	function sanitizeArray( array $array ): array
	{
		return security()->sanitizeArray( $array );
	}
}

if ( !function_exists( 'sanitizeText' ) ) {
	function sanitizeText( string|null $text = '' ): string
	{
		return security()->sanitizeText( $text );
	}
}

if ( !function_exists( 'escHtml' ) ) {
	function escHtml( string|null $string = '' ): string
	{
		return security()->escHtml( $string );
	}
}

if ( !function_exists( 'escAttr' ) ) {
	function escAttr( string|null $string = '' ): string
	{
		return security()->escAttr( $string );
	}
}

if ( !function_exists( 'escUrl' ) ) {
	function escUrl( string|null $string = '' ): string
	{
		return security()->escUrl( $string );
	}
}

if ( !function_exists( 'escJs' ) ) {
	function escJs( string|null $string = '' ): string
	{
		return security()->escJs( $string );
	}
}

if ( !function_exists( 'escCss' ) ) {
	function escCss( string|null $string = '' ): string
	{
		return security()->escCss( $string );
	}
}

if ( !function_exists( 'kses' ) ) {
	function kses( string|null $string = '' ): string
	{
		return security()->kses( $string );
	}
}

