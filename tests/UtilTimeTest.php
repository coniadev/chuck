<?php

declare(strict_types=1);

use Chuck\Util\Time;


test('ISO dates', function () {
    expect(Time::toIsoDate(TIMESTAMP))->toBe('2022-01-30');
    expect(Time::toIsoDateTime(TIMESTAMP))->toBe('2022-01-30 12:33:13');
});
