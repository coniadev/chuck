<?php

declare(strict_types=1);

use Conia\Chuck\Config;
use Conia\Chuck\ConfigInterface;
use Conia\Chuck\Request;
use Conia\Chuck\RequestInterface;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Error\Unresolvable;
use Conia\Chuck\Error\UntypedResolveParameter;
use Conia\Chuck\Tests\Fixtures\TestClass;
use Conia\Chuck\Tests\Fixtures\TestClassUntypedConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassWithConstructor;

test('Add value with key', function () {
    $registry = new Registry();
    $registry->add('registry', Registry::class);

    expect($registry->get('registry'))->toBe(Registry::class);
});


test('Check if registered', function () {
    $registry = new Registry();
    $registry->add(RequestInterface::class, Request::class);

    expect($registry->has(RequestInterface::class))->toBe(true);
    expect($registry->has('registry'))->toBe(false);
});


test('Instantiate', function () {
    $registry = new Registry();
    $registry->add('registry', Registry::class);
    $registry->add('request', Request::class);
    $reg = $registry->new('registry');
    $req = $registry->new('request', new Config('chuck'));

    expect($reg instanceof Registry)->toBe(true);
    expect($req instanceof Request)->toBe(true);
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

    expect($registry->resolve('class') instanceof stdClass)->toBe(true);
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
