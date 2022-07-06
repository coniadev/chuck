<?php

declare(strict_types=1);

use Conia\Chuck\Util\Arrays;


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
