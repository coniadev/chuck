<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Util\Arrays;
use Chuck\Util\I18n;
use Chuck\Util\Path;
use Chuck\Util\Strings;

uses(TestCase::class);

const TIMESTAMP = 1643545993; // 2022-01-30 13:33:13


test('Parse floats', function () {
    expect(I18n::parseFloat('13,23'))->toBe(13.23);
    expect(I18n::parseFloat('13.23'))->toBe(13.23);
    expect(I18n::parseFloat('13,73,83.23'))->toBe(137383.23);
    expect(I18n::parseFloat('23.738.312.2300'))->toBe(23738312.23);
    expect(I18n::parseFloat('23,738.300'))->toBe(23738.3);
    expect(I18n::parseFloat('1'))->toBe(1.0);
    expect(I18n::parseFloat(' 1,00 '))->toBe(1.0);
    expect(I18n::parseFloat("\n1.00 \t\n"))->toBe(1.0);
    expect(I18n::parseFloat(',00'))->toBe(0.0);
    expect(I18n::parseFloat(',0007'))->toBe(0.0007);
    expect(I18n::parseFloat('.003'))->toBe(0.003);
});


test('Parse invalid floats 1', function () {
    expect(I18n::parseFloat('13,00h'))->toBe(1.0);
})->throws(\ValueError::class);


test('Parse invalid floats 2', function () {
    expect(I18n::parseFloat('h23.00'))->toBe(1.0);
})->throws(\ValueError::class);


test('Localize date', function () {
    expect(I18n::localizeDate(TIMESTAMP, 'en'))->toBe('Jan 30, 2022');
    expect(I18n::localizeDate(TIMESTAMP, 'de'))->toBe('30.01.2022');
    expect(I18n::localizeDate(
        TIMESTAMP,
        'de',
        \IntlDateFormatter::SHORT,
    ))->toBe('30.01.22');
    expect(I18n::localizeDate(
        TIMESTAMP,
        'en',
    ))->toBe('Jan 30, 2022');
    expect(I18n::localizeDate(
        TIMESTAMP,
        'en',
        tz: 'Antarctica/South_Pole',
    ))->toBe('Jan 31, 2022');
    expect(I18n::localizeDate(
        TIMESTAMP,
        'de@calendar=buddhist',
        calendar: \IntlDateFormatter::TRADITIONAL,
    ))->toBe('30.01.2565 BE');
});


test('Localize date and time', function () {
    expect(I18n::localizeDateTime(TIMESTAMP, 'en'))->toBe('Jan 30, 2022, 12:33:13 PM');
    expect(I18n::localizeDateTime(TIMESTAMP, 'de'))->toBe('30.01.2022, 12:33:13');
    expect(I18n::localizeDateTIME(
        TIMESTAMP,
        'de',
        \IntlDateFormatter::SHORT,
        \IntlDateFormatter::LONG,
    ))->toBe('30.01.22, 12:33:13 UTC');
    expect(I18n::localizeDateTIME(
        TIMESTAMP,
        'en',
        \IntlDateFormatter::LONG,
        \IntlDateFormatter::SHORT,
        tz: 'Antarctica/Casey',
    ))->toBe('January 30, 2022 at 8:33 PM');
    expect(I18n::localizeDateTime(
        TIMESTAMP,
        'de@calendar=japanese',
        tz: 'CET',
        calendar: \IntlDateFormatter::TRADITIONAL,
    ))->toBe('30.01.4 Reiwa, 13:33:13');
});


test('Array group by', function () {
    $data = [
        ['key' => 'leprosy', 'value' => 13],
        ['key' => 'symbolic', 'value' => 31],
        ['key' => 'leprosy', 'value' => 17],
        ['key' => 'leprosy', 'value' => 23],
        ['key' => 'symbolic', 'value' => 37],
        ['key' => 'symbolic', 'value' => 41],
        ['key' => 'leprosy', 'value' => 29],
    ];

    expect(Arrays::groupBy($data, 'key'))->toBe(
        [
            'leprosy' => [
                ['key' => 'leprosy', 'value' => 13],
                ['key' => 'leprosy', 'value' => 17],
                ['key' => 'leprosy', 'value' => 23],
                ['key' => 'leprosy', 'value' => 29],
            ],
            'symbolic' => [
                ['key' => 'symbolic', 'value' => 31],
                ['key' => 'symbolic', 'value' => 37],
                ['key' => 'symbolic', 'value' => 41],
            ]
        ]
    );
});


test('Array is assoc', function () {
    expect(Arrays::isAssoc([]))->toBe(false);
    expect(Arrays::isAssoc([1, 2, 3]))->toBe(false);
    expect(Arrays::isAssoc(['leprosy' => 1, 'symbolic' => 2]))->toBe(true);
    expect(Arrays::isAssoc([1 => 1, 2 => 2]))->toBe(true);
});


test('String entropy', function () {
    $lower = Strings::entropy('spirit crusher');
    $upper = Strings::entropy('SPIRIT CRUSHER');
    $mixed = Strings::entropy('Spirit Crusher');

    expect($lower)->toBe($upper);
    expect($lower)->toBeLessThan($mixed);
    expect(Strings::entropy('Correct Horse Battery Staple'))->toBeGreaterThan(100);
    expect(Strings::entropy('evil-chuck-666'))->toBeGreaterThan(40);
    expect(Strings::entropy('acegik'))->toBeLessThan(15);
    expect(Strings::entropy('12345'))->toBeLessThan(10);
    expect(Strings::entropy('1'))->toBe(0.0);
});


test('Path realpath', function () {
    expect(
        Path::realpath('/perserverance/./of/././the/../time')
    )->toBe('/perserverance/of/time');
    expect(
        Path::realpath('spiritual/../../../healing')
    )->toBe('healing');
});


test('Path is inside root dir', function () {
    $root = dirname(__DIR__);
    $config = $this->getConfig(['path' => ['root' => $root]]);
    $pathUtil = new Path($config);

    expect($pathUtil->insideRoot("$root/../leprosy"))->toBe(false);
    expect($pathUtil->insideRoot("$root/symbolic"))->toBe(true);
    expect($pathUtil->insideRoot("$root/././/./symbolic"))->toBe(true);
    expect($pathUtil->insideRoot("$root/./..//./symbolic"))->toBe(false);
    expect($pathUtil->insideRoot("/etc/apache"))->toBe(false);
});
