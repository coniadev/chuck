<?php

declare(strict_types=1);

use Chuck\Util\I18n;

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
