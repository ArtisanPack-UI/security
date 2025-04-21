<?php
test( 'escape html', function () {
    expect( escHtml( '<p>This is a paragraph</p>' ) )->toEqual( '&lt;p&gt;This is a paragraph&lt;/p&gt;' );
} );

test( 'escape url', function () {
    expect( escUrl( 'https://digitalshopfrontcms.com/this is a url' ) )->toEqual( 'https%3A%2F%2Fdigitalshopfrontcms.com%2Fthis%20is%20a%20url' )
                                                                       ->and( escUrl( 'https://digitalshopfrontcms.com' ) )->toEqual( 'https%3A%2F%2Fdigitalshopfrontcms.com' );
} );

test( 'escaping attr', function () {
    expect( escAttr( '<p>This is a test</p>' ) )->toEqual( '&lt;p&gt;This&#x20;is&#x20;a&#x20;test&lt;&#x2F;p&gt;' );
} );

test( 'escaping js', function () {
    expect( escJs( '<script>
        let testVar = "";
        console.log(testVar);</script>' ) )->toEqual( '\x3Cscript\x3E\x0A\x20\x20\x20\x20\x20\x20\x20\x20let\x20testVar\x20\x3D\x20\x22\x22\x3B\x0A\x20\x20\x20\x20\x20\x20\x20\x20console.log\x28testVar\x29\x3B\x3C\x2Fscript\x3E' );
} );

test( 'escaping css', function () {
    expect( escCss( '.class-name {background-color: #000000;}' ) )->toEqual( '\2E class\2D name\20 \7B background\2D color\3A \20 \23 000000\3B \7D ' );
} );

test( 'escaping kses', function () {
    expect( kses( '<div class="test-div">
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
            labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
            aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum
            dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
            deserunt mollit anim id est laborum.</p>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
            labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
            aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum
            dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
            deserunt mollit anim id est laborum.</p>
        </div>' ) )->toEqual( '<div class="test-div">
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
            labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
            aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum
            dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
            deserunt mollit anim id est laborum.</p>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
            labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
            aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum
            dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
            deserunt mollit anim id est laborum.</p>
        </div>' );
} );
