<?php

declare(strict_types=1);

use Conia\Chuck\Registry\Resolver;
use Conia\Chuck\Tests\Fixtures\TestClass;
use Conia\Chuck\Tests\Fixtures\TestClassResolver;
use Conia\Chuck\Tests\Fixtures\TestClassResolverDefault;
use Conia\Chuck\Tests\Fixtures\TestClassWithConstructor;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Simple autowiring', function () {
    $resolver = new Resolver($this->registry());

    expect($resolver->autowire(TestClassWithConstructor::class))
        ->toBeInstanceOf(TestClassWithConstructor::class);
});


test('Autowiring with partial args', function () {
    $resolver = new Resolver($this->registry());
    $tc = $resolver->autowire(TestClassResolver::class, ['name' => 'chuck', 'number' => 73]);

    expect($tc)->toBeInstanceOf(TestClassResolver::class);
    expect($tc->name)->toBe('chuck');
    expect($tc->number)->toBe(73);
    expect($tc->tc)->toBeInstanceOf(TestClass::class);
});


test('Autowiring with partial args and default values', function () {
    $resolver = new Resolver($this->registry());
    $tc = $resolver->autowire(TestClassResolverDefault::class, ['number' => 73]);

    expect($tc)->toBeInstanceOf(TestClassResolverDefault::class);
    expect($tc->name)->toBe('default');
    expect($tc->number)->toBe(73);
    expect($tc->tc)->toBeInstanceOf(TestClass::class);
});


test('Get constructor args', function () {
    $resolver = new Resolver($this->registry());
    $args = $resolver->resolveConstructorArgs(TestClassWithConstructor::class);

    expect($args[0])->toBeInstanceOf(TestClass::class);
});


test('Get closure args', function () {
    $resolver = new Resolver($this->registry());
    $args = $resolver->resolveCallableArgs(function (Testclass $tc, int $number = 13) {
    });

    expect($args[0])->toBeInstanceOf(TestClass::class);
    expect($args[1])->toBe(13);
});


test('Get callable object args', function () {
    $resolver = new Resolver($this->registry());
    $tc = $resolver->autowire(TestClass::class);
    $args = $resolver->resolveCallableArgs($tc);

    expect($args[0])->toBe('default');
    expect($args[1])->toBe(13);
});
