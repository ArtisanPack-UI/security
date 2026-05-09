<?php

declare(strict_types=1);
test('sanitize emails', function (): void {
    expect(sanitizeEmail('goodÂ@bad.com'))->toEqual('good@bad.com')
        ->and(sanitizeEmail('mikeq@google.com'))->toEqual('mikeq@google.com')
        ->and(sanitizeEmail('puser@porsche.us'))->toEqual('puser@porsche.us')
        ->and(sanitizeEmail('<yo@marist.edu>'))->toEqual('yo@marist.edu');
});

test('sanitize urls', function (): void {
    expect(sanitizeUrl('goodÂ.com'))->toEqual('good.com');
});

test('sanitize filenames', function (): void {
    expect(sanitizeFilename('goodÂ.com'))->toEqual('goodÂ.com');
});

test('sanitize passwords', function (): void {
    expect(sanitizePassword('goodÂ.com'))->toEqual('goodÂ.com');
});

test('sanitize integers', function (): void {
    expect(sanitizeInt('21'))->toBeInt()->toEqual(21)
        ->and(sanitizeInt('24.3'))->toBeInt()->toEqual(24);
});

test('sanitize dates', function (): void {
    expect(sanitizeDate('2025-02-02'))->toEqual('2025-02-02')
        ->and(sanitizeDate('January 2, 2025'))->toEqual('2025-01-02');
});

test('sanitize datetimes', function (): void {
    expect(sanitizeDatetime('2025-02-02 01:02:03'))->toEqual('2025-02-02 01:02:03')
        ->and(sanitizeDatetime('January 2, 2025 3 p.m.'))->toEqual('2025-01-02 15:00:00');
});

test('sanitize strings', function (): void {
    expect(sanitizeText('January 2, 2025 3 p.m.'))->toEqual('January 2, 2025 3 p.m.')
        ->and(sanitizeText('<p>This is a paragraph</p>'))->toEqual('This is a paragraph');
});

test('sanitize arrays', function (): void {
    $arrayToTest = [
        'array_key'       => 'array_value',
        'wrong array key' => '<p>wrong array value</p>',
    ];

    $arrayToCheck = [
        'array_key'       => 'array_value',
        'wrong array key' => 'wrong array value',
    ];

    expect(sanitizeArray($arrayToTest))->toEqual($arrayToCheck);
});
