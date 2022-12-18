<?php

declare(strict_types=1);

// use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\Registry;

// uses(TestCase::class);

test('Add value without key', function () {
    $registry = new Registry();
    $registry->add(Registry::class);

    expect($registry->get(Registry::class))->toBe(Registry::class);
});


test('Add value with key', function () {
    $registry = new Registry();
    $registry->add('registry', Registry::class);

    expect($registry->get('registry'))->toBe(Registry::class);
});


test('Check if registered', function () {
    $registry = new Registry();
    $registry->add(Registry::class);

    expect($registry->has(Registry::class))->toBe(true);
    expect($registry->has('registry'))->toBe(false);
});


test('Instantiate', function () {
    $registry = new Registry();
    $registry->add(Registry::class);
    $r = $registry->new(Registry::class);

    expect(is_a($r, Registry::class))->toBe(true);
});


test('Fail if key does not exist', function () {
    $registry = new Registry();
    $registry->get('registry');
})->throws(OutOfBoundsException::class);
