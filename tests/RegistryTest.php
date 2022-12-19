<?php

declare(strict_types=1);

use Conia\Chuck\Registry;
use Conia\Chuck\Error\Unresolvable;
use Conia\Chuck\Error\UntypedResolveParameter;
use Conia\Chuck\Tests\Fixtures\TestClass;
use Conia\Chuck\Tests\Fixtures\TestClassUntypedConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassWithConstructor;

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


test('Resolve instance', function () {
    $registry = new Registry();
    $object = new stdClass();
    $registry->add('object', $object);

    expect($registry->resolve('object'))->toBe($object);
});


test('Resolve simple class', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class);

    expect($registry->resolve('class')::class)->toBe(stdClass::class);
});


test('Resolve simple class where id is the class name', function () {
    $registry = new Registry();
    $registry->add(stdClass::class);

    expect($registry->resolve(stdClass::class)::class)->toBe(stdClass::class);
});


test('Resolve class with constructor', function () {
    $registry = new Registry();

    $object = $registry->resolve(TestClassWithConstructor::class);

    expect($object::class)->toBe(TestClassWithConstructor::class);
    expect($object->tc::class)->toBe(TestClass::class);
});


test('Resolve class with untyped constructor', function () {
    $registry = new Registry();

    $registry->resolve(TestClassUntypedConstructor::class);
})->throws(UntypedResolveParameter::class);


test('Resolve unresolvable class', function () {
    $registry = new Registry();

    $registry->resolve(GdImage::class);
})->throws(Unresolvable::class, 'Details:');


test('Resolve non existent class', function () {
    $registry = new Registry();

    $registry->resolve('NonExistent');
})->throws(Unresolvable::class, 'NonExistent');
