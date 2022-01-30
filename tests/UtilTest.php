<?php

declare(strict_types=1);

use Chuck\Util\I18n;

const TIMESTAMP = 1643545993; // 2022-01-30

test('parse floats', function () {
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

test('parse invalid floats 1', function () {
    expect(I18n::parseFloat('13,00h'))->toBe(1.0);
})->throws(\ValueError::class);

test('parse invalid floats 2', function () {
    expect(I18n::parseFloat('h23.00'))->toBe(1.0);
})->throws(\ValueError::class);

test('localize date', function () {
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

test('localize date and time', function () {
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
