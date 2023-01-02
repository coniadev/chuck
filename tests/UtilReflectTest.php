<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\Util\Reflect;
use Conia\Chuck\Request;
use Conia\Chuck\Response\Response;

uses(TestCase::class);


test('Reflect function', function () {
    $rf = Reflect::getReflectionFunction(function () {
    });
    expect($rf)->toBeInstanceOf(ReflectionFunction::class);

    $rf = Reflect::getReflectionFunction(new class
    {
        public function __invoke(): string
        {
            return '';
        }
    });
    expect($rf)->toBeInstanceOf(ReflectionMethod::class);

    $rf = Reflect::getReflectionFunction('is_string');
});


test('Implements RequestInterface', function () {
    $rf = Reflect::getReflectionFunction(function (Request $_): mixed {
        return null;
    });
    expect(Reflect::paramImplementsRequestInterface($rf->getParameters()[0]))->toBe(true);

    $rf = Reflect::getReflectionFunction(function ($_): mixed {
        return null;
    });
    expect(Reflect::paramImplementsRequestInterface($rf->getParameters()[0]))->toBe(false);

    $rf = Reflect::getReflectionFunction('is_string');
    expect(Reflect::paramImplementsRequestInterface($rf->getParameters()[0]))->toBe(false);
});
