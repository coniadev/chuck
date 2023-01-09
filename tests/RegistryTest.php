<?php

declare(strict_types=1);

use Conia\Chuck\Config;
use Conia\Chuck\Request;
use Conia\Chuck\Registry;
use Conia\Chuck\RegistryEntry;
use Conia\Chuck\Exception\NotFoundException;
use Conia\Chuck\Exception\ContainerException;
use Conia\Chuck\Tests\Fixtures\TestClass;
use Conia\Chuck\Tests\Fixtures\TestClassRegistryArgs;
use Conia\Chuck\Tests\Fixtures\TestClassRegistrySingleArg;
use Conia\Chuck\Tests\Fixtures\TestClassRegistryNamedParam;
use Conia\Chuck\Tests\Fixtures\TestClassIntersectionTypeConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassUnionTypeConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassUntypedConstructor;
use Conia\Chuck\Tests\Fixtures\TestClassWithConstructor;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);

test('Entry methods', function () {
    $entry = new RegistryEntry('key', stdClass::class);

    expect($entry->definition())->toBe(stdClass::class);
    expect($entry->get())->toBe(stdClass::class);
    expect($entry->instance())->toBe(null);

    $obj = new stdClass();
    $entry->set($obj);

    expect($entry->definition())->toBe(stdClass::class);
    expect($entry->get())->toBe($obj);
    expect($entry->instance())->toBe($obj);
});


test('Add value with key', function () {
    $registry = new Registry();
    $registry->add(Config::class, new Config('unbound'));
    $registry->add(Config::class, new Config('bound'), 'bound');

    expect($registry->entry(Config::class, 'bound')->definition()->app())->toBe('bound');
    expect($registry->entry(Config::class)->definition()->app())->toBe('unbound');
});


test('Add key without value', function () {
    $registry = new Registry();
    $registry->add(Config::class);

    expect($registry->entry(Config::class)->definition())->toBe(Config::class);
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
    $req = $registry->new('request', $this->psr7Request());

    expect($reg instanceof Registry)->toBe(true);
    expect($req instanceof Request)->toBe(true);
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


test('Resolve class named parameter', function () {
    // with $
    $registry = new Registry();
    $registry->add(Config::class, new Config('chuck'));
    $registry->add(Config::class, new Config('$named'), '$namedConfig');

    $object = $registry->get(TestClassRegistryNamedParam::class);

    expect($object->config->app())->toBe('chuck');
    expect($object->namedConfig->app())->toBe('$named');

    // without $
    $registry = new Registry();
    $registry->add(Config::class, new Config('chuck'));
    $registry->add(Config::class, new Config('named'), 'namedConfig');

    $object = $registry->get(TestClassRegistryNamedParam::class);

    expect($object->config->app())->toBe('chuck');
    expect($object->namedConfig->app())->toBe('named');
});


test('Get named parameter entry', function () {
    $registry = new Registry();
    $registry->add(Config::class, new Config('named'), '$namedConfig');
    $registry->add(Config::class, new Config('chuck'));

    $config1 = $registry->get(Config::class);
    $config2 = $registry->getWithParamName(Config::class, 'namedConfig');

    expect($config1->app())->toBe('chuck');
    expect($config2->app())->toBe('named');

    $config3 = $registry->getWithParamName(Config::class, '$namedConfig');
    $config4 = $registry->getWithParamName(Config::class, '$wrongName');

    expect($config3->app())->toBe('named');
    expect($config4->app())->toBe('chuck');

    expect($config1)->toBe($config4);
    expect($config2)->toBe($config3);
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
    $instance = $registry->get('class');

    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof Config)->toBe(true);
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
})->throws(NotFoundException::class, 'Unresolvable id: string');


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
    $instance = $registry->get('class');

    expect($instance instanceof TestClassRegistryArgs)->toBe(true);
    expect($instance->tc instanceof TestClass)->toBe(true);
    expect($instance->config instanceof Config)->toBe(true);
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


test('Reject closure with args', function () {
    $registry = new Registry();
    $registry->add('class', function () {
        return new stdClass();
    })->args(['value' => 'chuck']);
})->throws(ContainerException::class, 'Closure definitions');


test('Is reified', function () {
    $registry = new Registry();
    $registry->add('class', stdClass::class);
    $obj1 = $registry->get('class');
    $obj2 = $registry->get('class');

    expect($obj1 === $obj2)->toBe(true);
});


test('As is', function () {
    $registry = new Registry();
    $registry->add('closure1', fn () =>'called');
    $registry->add('closure2', fn () =>'notcalled')->asIs();
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
    $registry->tag('tag')->add(Config::class);

    expect($registry->tag('tag')->entry(Config::class)->definition())->toBe(Config::class);
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


test('Third party container', function () {
    $container = new League\Container\Container();
    $container->add('external', new stdClass());
    $registry = new Registry($container);
    $registry->addAnyway('internal', new Registry());

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


test('Reject adding when third party container is used', function () {
    $container = new League\Container\Container();
    $registry = new Registry($container);
    $registry->add('internal', new Registry());
})->throws(ContainerException::class, 'Third party container');


test('Getting non existent tagged entry fails', function () {
    $registry = new Registry();

    $registry->tag('tag')->get('NonExistent');
})->throws(NotFoundException::class, 'Unresolvable tagged id: tag::NonExistent');
