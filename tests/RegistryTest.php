<?php

declare(strict_types=1);

use Conia\Chuck\Config;
use Conia\Chuck\Request;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Exception\UnresolvableException;
use Conia\Chuck\Tests\Fixtures\TestClass;
use Conia\Chuck\Tests\Fixtures\TestClassRegistryArgs;
use Conia\Chuck\Tests\Fixtures\TestClassRegistryNamedParam;
use Conia\Chuck\Tests\Fixtures\TestClassIntersectionTypeConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassUnionTypeConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassUntypedConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassWithConstructor;

test('Add value with key', function () {
    $registry = new Registry();
    $registry->add('registry', Registry::class);

    expect($registry->get('registry'))->toBe(Registry::class);
});


test('Check if registered', function () {
    $registry = new Registry();
    $registry->add(Registry::class, $registry);

    expect($registry->has(Registry::class))->toBe(true);
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


test('Resolve class named parameter', function () {
    $registry = new Registry();
    $registry->add(Config::class, new Config('chuck'));
    $registry->add(Config::class, new Config('named'), '$namedConfig');

    $object = $registry->resolve(TestClassRegistryNamedParam::class);

    expect($object->config->app())->toBe('chuck');
    expect($object->namedConfig->app())->toBe('named');
});


test('Resolve closure class', function () {
    $registry = new Registry();
    $registry->add(Config::class, new Config('chuck'));
    $registry->add('class', function (Config $config) {
        return new TestClassRegistryArgs(
            new TestClass(),
            'chuck',
            $config,
        );
    });
    $instance = $registry->resolve('class');

    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof Config)->toBe(true);
    expect($instance->test)->toBe('chuck');
});


test('Resolve with args array', function () {
    $registry = new Registry();
    $registry->add('class', TestClassRegistryArgs::class)->args([
        'test' => 'chuck',
        'tc' => new TestClass(),
    ]);
    $instance = $registry->resolve('class');

    expect($instance instanceof TestClassRegistryArgs)->toBe(true);
    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->test)->toBe('chuck');
});


test('Resolve with args closure', function () {
    $registry = new Registry();
    $registry->add(Config::class, new Config('chuck'));
    $registry->add('class', TestClassRegistryArgs::class)->args(function (Config $config) {
        return [
            'test' => 'chuck',
            'tc' => new TestClass(),
            'config' => $config,
        ];
    });
    $instance = $registry->resolve('class');

    expect($instance instanceof TestClassRegistryArgs)->toBe(true);
    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof Config)->toBe(true);
    expect($instance->test)->toBe('chuck');
});


test('Is reified', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class);
    $obj1 = $registry->resolve('class');
    $obj2 = $registry->resolve('class');

    expect($obj1 === $obj2)->toBe(true);
});


test('Is not reified', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class)->reify(false);
    $obj1 = $registry->resolve('class');
    $obj2 = $registry->resolve('class');

    expect($obj1 === $obj2)->toBe(false);
});


test('Parameter info class', function () {
    $rc = new ReflectionClass(TestClassUnionTypeConstructor::class);
    $c = $rc->getConstructor();
    $p = $c->getParameters()[0];
    $registry = new Registry();
    $s = 'Conia\Chuck\Tests\Fixtures\TestClassUnionTypeConstructor::__construct(' .
        '..., Conia\Chuck\Config|Conia\Chuck\Request $param, ...)';

    expect($registry->getParamInfo($p))->toBe($s);
});


test('Parameter info function', function () {
    $rf = new ReflectionFunction(function (Config $config) {
    });
    $p = $rf->getParameters()[0];
    $registry = new Registry();
    $s = 'P\Tests\RegistryTest::{closure}(..., Conia\Chuck\Config $config, ...)';

    expect($registry->getParamInfo($p))->toBe($s);
});


test('Reject class with untyped constructor', function () {
    $registry = new Registry();

    $registry->resolve(TestClassUntypedConstructor::class);
})->throws(UnresolvableException::class, 'typed constructor parameters');


test('Reject class with unsupported constructor union types', function () {
    $registry = new Registry();

    $registry->resolve(TestClassUnionTypeConstructor::class);
})->throws(UnresolvableException::class, 'union or intersection');


test('Reject class with unsupported constructor intersection types', function () {
    $registry = new Registry();

    $registry->resolve(TestClassIntersectionTypeConstructor::class);
})->throws(UnresolvableException::class, 'union or intersection');


test('Reject unresolvable class', function () {
    $registry = new Registry();

    $registry->resolve(GdImage::class);
})->throws(UnresolvableException::class, 'unresolvable');


test('Reject non existent class', function () {
    $registry = new Registry();

    $registry->resolve('NonExistent');
})->throws(UnresolvableException::class, 'NonExistent');


test('Reject $id == $value', function () {
    $registry = new Registry();

    $registry->add('chuck', 'chuck');
})->throws(RuntimeException::class, 'must be different');


test('Reject closure with args', function () {
    $registry = new Registry();
    $registry->add('class', function () {
        return new stdClass();
    })->args(['value' => 'chuck']);
})->throws(RuntimeException::class, 'Closure values');


test('Reject named entry not starting with $', function () {
    $registry = new Registry();
    $registry->add(Config::class, new stdClass(), 'named');
})->throws(RuntimeException::class, 'must start with');
