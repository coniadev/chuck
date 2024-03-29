<?php

declare(strict_types=1);

use Conia\Chuck\Di\Resolver;
use Conia\Chuck\Exception\ContainerException;
use Conia\Chuck\Exception\NotFoundException;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Tests\Fixtures\TestClass;
use Conia\Chuck\Tests\Fixtures\TestClassIntersectionTypeConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassRegistryArgs;
use Conia\Chuck\Tests\Fixtures\TestClassRegistrySingleArg;
use Conia\Chuck\Tests\Fixtures\TestClassUnionTypeConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassUntypedConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassWithConstructor;
use Conia\Chuck\Tests\Fixtures\TestConfig;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);

test('Add key without value', function () {
    $registry = new Registry();
    $registry->add(TestConfig::class);

    expect($registry->entry(TestConfig::class)->definition())->toBe(TestConfig::class);
});

test('Entry instance and value', function () {
    $registry = new Registry();
    $registry->add(stdClass::class);

    expect($registry->entry(stdClass::class)->definition())->toBe(stdClass::class);
    expect($registry->entry(stdClass::class)->instance())->toBe(null);
    expect($registry->entry(stdClass::class)->get())->toBe(stdClass::class);

    $obj = $registry->get(stdClass::class);

    expect($obj instanceof stdClass)->toBe(true);
    expect($registry->entry(stdClass::class)->definition())->toBe(stdClass::class);
    expect($registry->entry(stdClass::class)->instance())->toBe($obj);
    expect($registry->entry(stdClass::class)->get())->toBe($obj);
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
    $req = $registry->new('request', $this->psrRequest());

    expect($reg instanceof Registry)->toBe(true);
    expect($req instanceof Request)->toBe(true);
});

test('Instantiate with call', function () {
    $registry = new Registry();
    $registry->add(TestClass::class)->call('init', value: 'testvalue');
    $tc = $registry->get(TestClass::class);

    expect($tc instanceof TestClass)->toBe(true);
    expect($tc->value)->toBe('testvalue');
});

test('Chained instantiation', function () {
    $registry = new Registry();
    $registry->add(
        Psr\Container\ContainerExceptionInterface::class,
        Psr\Container\NotFoundExceptionInterface::class
    );
    $registry->add(
        Psr\Container\NotFoundExceptionInterface::class,
        NotFoundException::class
    );
    $exception = $registry->new(
        Psr\Container\ContainerExceptionInterface::class,
        'The message',
        13
    );

    expect($exception instanceof NotFoundException)->toBe(true);
    expect($exception->getMessage())->toBe('The message');
    expect($exception->getCode())->toBe(13);
});

test('Factory method instantiation', function () {
    $registry = new Registry();
    $registry->add(TestClassRegistryArgs::class)->constructor('fromDefaults');
    $instance = $registry->get(TestClassRegistryArgs::class);

    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof TestConfig)->toBe(true);
    expect($instance->config->app())->toBe('fromDefaults');
    expect($instance->test)->toBe('fromDefaults');
});

test('Factory method instantiation with args', function () {
    $registry = new Registry();
    $registry
        ->add(TestClassRegistryArgs::class)
        ->constructor('fromArgs')
        ->args(test: 'passed', app: 'passed');
    $instance = $registry->get(TestClassRegistryArgs::class);

    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof TestConfig)->toBe(true);
    expect($instance->config->app())->toBe('passed');
    expect($instance->test)->toBe('passed');
});

test('Autowired instantiation', function () {
    $registry = new Registry();

    expect($registry->new(NotFoundException::class) instanceof NotFoundException)->toBe(true);
});

test('Autowired instantiation fails', function () {
    $registry = new Registry();

    expect($registry->new(NoValidClass::class) instanceof NotFoundException)->toBe(true);
})->throws(NotFoundException::class, 'Cannot instantiate NoValidClass');

test('Resolve instance', function () {
    $registry = new Registry();
    $object = new stdClass();
    $registry->add('object', $object);

    expect($registry->get('object'))->toBe($object);
});

test('Resolve simple class', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class);

    expect($registry->get('class') instanceof stdClass)->toBe(true);
});

test('Resolve chained entry', function () {
    $registry = new Registry();
    $registry->add(
        Psr\Container\ContainerExceptionInterface::class,
        Psr\Container\NotFoundExceptionInterface::class
    );
    $registry->add(
        Psr\Container\NotFoundExceptionInterface::class,
        NotFoundException::class
    );

    expect($registry->get(
        Psr\Container\ContainerExceptionInterface::class
    ) instanceof NotFoundException)->toBe(true);
});

test('Resolve class with constructor', function () {
    $registry = new Registry();

    $object = $registry->get(TestClassWithConstructor::class);

    expect($object::class)->toBe(TestClassWithConstructor::class);
    expect($object->tc::class)->toBe(TestClass::class);
});

test('Resolve closure class', function () {
    $registry = new Registry();
    $registry->add(TestConfig::class, new TestConfig('chuck'));
    $registry->add('class', function (TestConfig $config) {
        return new TestClassRegistryArgs(
            new TestClass(),
            'chuck',
            $config,
        );
    });
    $instance = $registry->get('class');

    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof TestConfig)->toBe(true);
    expect($instance->test)->toBe('chuck');
});

test('Reject class with untyped constructor', function () {
    $registry = new Registry();

    $registry->get(TestClassUntypedConstructor::class);
})->throws(ContainerException::class, 'typed constructor parameters');

test('Reject class with unsupported constructor union types', function () {
    $registry = new Registry();

    $registry->get(TestClassUnionTypeConstructor::class);
})->throws(ContainerException::class, 'union or intersection');

test('Reject class with unsupported constructor intersection types', function () {
    $registry = new Registry();

    $registry->get(TestClassIntersectionTypeConstructor::class);
})->throws(ContainerException::class, 'union or intersection');

test('Reject unresolvable class', function () {
    $registry = new Registry();

    $registry->get(GdImage::class);
})->throws(ContainerException::class, 'unresolvable');

test('Getting non existent class fails', function () {
    $registry = new Registry();

    $registry->get('NonExistent');
})->throws(NotFoundException::class, 'NonExistent');

test('Getting non resolvable entry fails', function () {
    $registry = new Registry();
    $registry->add('unresolvable', InvalidClass::class);

    $registry->get('unresolvable');
})->throws(NotFoundException::class, 'Unresolvable id: InvalidClass');

test('Rejecting class with non resolvable params', function () {
    $registry = new Registry();
    $registry->add('unresolvable', TestClassRegistryArgs::class);

    $registry->get('unresolvable');
})->throws(ContainerException::class, 'Unresolvable id: string');

test('Resolve with args array', function () {
    $registry = new Registry();
    $registry->add('class', TestClassRegistryArgs::class)->args([
        'test' => 'chuck',
        'tc' => new TestClass(),
    ]);
    $instance = $registry->get('class');

    expect($instance instanceof TestClassRegistryArgs)->toBe(true);
    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->test)->toBe('chuck');
});

test('Resolve with single named arg array', function () {
    $registry = new Registry();
    $registry->add('class', TestClassRegistrySingleArg::class)->args(
        test: 'chuck',
    );
    $instance = $registry->get('class');

    expect($instance instanceof TestClassRegistrySingleArg)->toBe(true);
    expect($instance->test)->toBe('chuck');
});

test('Resolve with named args array', function () {
    $registry = new Registry();
    $registry->add('class', TestClassRegistryArgs::class)->args(
        test: 'chuck',
        tc: new TestClass(),
    );
    $instance = $registry->get('class');

    expect($instance instanceof TestClassRegistryArgs)->toBe(true);
    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->test)->toBe('chuck');
});

test('Resolve closure class with args', function () {
    $registry = new Registry();
    $registry->add(TestConfig::class, new TestConfig('chuck'));
    $registry->add('class', function (TestConfig $config, string $name, TestClass $tc) {
        return new TestClassRegistryArgs($tc, $name, $config);
    })->args(config: new TestConfig('chuck'), tc: new TestClass(), name: 'chuck');
    $instance = $registry->get('class');

    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof TestConfig)->toBe(true);
    expect($instance->test)->toBe('chuck');
});

test('Resolve with args closure', function () {
    $registry = new Registry();
    $registry->add(TestConfig::class, new TestConfig('chuck'));
    $registry->add('class', TestClassRegistryArgs::class)->args(function (TestConfig $config) {
        return [
            'test' => 'chuck',
            'tc' => new TestClass(),
            'config' => $config,
        ];
    });
    $instance = $registry->get('class');

    expect($instance instanceof TestClassRegistryArgs)->toBe(true);
    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof TestConfig)->toBe(true);
    expect($instance->test)->toBe('chuck');
});

test('Resolve closure class with args closure', function () {
    $registry = new Registry();
    $registry->add('class', function (TestConfig $config, string $name, TestClass $tc) {
        return new TestClassRegistryArgs($tc, $name, $config);
    })->args(function () {
        return [
            'config' => new TestConfig('chuck'),
            'tc' => new TestClass(),
            'name' => 'chuck',
        ];
    });
    $instance = $registry->get('class');

    expect($instance instanceof TestClassRegistryArgs)->toBe(true);
    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof TestConfig)->toBe(true);
    expect($instance->test)->toBe('chuck');
});

test('Reject multiple unnamed args', function () {
    $registry = new Registry();
    $registry->add('class', function () {
        return new stdClass();
    })->args('chuck', 13);
})->throws(ContainerException::class, 'Registry entry arguments');

test('Reject single unnamed arg with wrong type', function () {
    $registry = new Registry();
    $registry->add('class', function () {
        return new stdClass();
    })->args('chuck');
})->throws(ContainerException::class, 'Registry entry arguments');

test('Is reified', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class);
    $obj1 = $registry->get('class');
    $obj2 = $registry->get('class');

    expect($obj1 === $obj2)->toBe(true);
});

test('As is', function () {
    $registry = new Registry();
    $registry->add('closure1', fn () => 'called');
    $registry->add('closure2', fn () => 'notcalled')->asIs();
    $value1 = $registry->get('closure1');
    $value2 = $registry->get('closure2');

    expect($value1)->toBe('called');
    expect($value2 instanceof Closure)->toBe(true);
});

test('Is not reified', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class)->reify(false);
    $obj1 = $registry->get('class');
    $obj2 = $registry->get('class');

    expect($obj1 === $obj2)->toBe(false);
});

test('Fetch entries list', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class)->reify(false);

    expect($registry->entries())->toBe(['class']);
    expect($registry->entries(includeRegistry: true))->toBe(
        ['Psr\Container\ContainerInterface', 'Conia\Chuck\Registry', 'class']
    );
});

test('Add and receive tagged entries', function () {
    $registry = new Registry();
    $registry->tag('tag')->add('class', stdClass::class);
    $obj = $registry->tag('tag')->get('class');
    $entry = $registry->tag('tag')->entry('class');

    expect($obj instanceof stdClass)->toBe(true);
    expect($entry->definition())->toBe(stdClass::class);
    expect($obj === $entry->instance())->toBe(true);
    expect($obj === $entry->get())->toBe(true);
    expect($registry->tag('tag')->has('class'))->toBe(true);
    expect($registry->tag('tag')->has('wrong'))->toBe(false);
    expect($registry->has('class'))->toBe(false);
});

test('Add tagged key without value', function () {
    $registry = new Registry();
    $registry->tag('tag')->add(TestConfig::class);

    expect($registry->tag('tag')->entry(TestConfig::class)->definition())->toBe(TestConfig::class);
});

test('Parameter info class', function () {
    $rc = new ReflectionClass(TestClassUnionTypeConstructor::class);
    $c = $rc->getConstructor();
    $p = $c->getParameters()[0];
    $resolver = new Resolver(new Registry());
    $s = 'Conia\Chuck\Tests\Fixtures\TestClassUnionTypeConstructor::__construct(' .
        '..., Conia\Chuck\Tests\Fixtures\TestConfig|Conia\Chuck\Request $param, ...)';

    expect($resolver->getParamInfo($p))->toBe($s);
});

test('Parameter info function', function () {
    $rf = new ReflectionFunction(function (TestConfig $config) {
        $config->set('test', 'test');
    });
    $p = $rf->getParameters()[0];
    $resolver = new Resolver(new Registry());
    $s = 'P\Tests\RegistryTest::{closure}(..., Conia\Chuck\Tests\Fixtures\TestConfig $config, ...)';

    expect($resolver->getParamInfo($p))->toBe($s);
});

test('Third party container', function () {
    $container = new League\Container\Container();
    $container->add('external', new stdClass());
    $registry = new Registry($container);
    $registry->add('internal', new Registry());

    expect($registry->get('external') instanceof stdClass)->toBe(true);
    expect($registry->get('internal') instanceof Registry)->toBe(true);
    expect($registry->get(
        Psr\Container\ContainerInterface::class
    ) instanceof League\Container\Container)->toBe(true);
    expect($registry->get(
        Psr\Container\ContainerInterface::class
    ))->toBe($container);
    expect($registry->get(League\Container\Container::class))->toBe($container);
});

test('Getting non existent tagged entry fails', function () {
    $registry = new Registry();

    $registry->tag('tag')->get('NonExistent');
})->throws(NotFoundException::class, 'Unresolvable id: NonExistent');
