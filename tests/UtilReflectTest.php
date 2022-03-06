<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Util\Reflect;
use Chuck\{Request, Response};

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


test('Middleware :: no return type', function () {
    Reflect::validateMiddleware(function (Request $request, callable $next) {
        return $next($request);
    });
})->throws(TypeError::class, 'Middleware return type must be given');


test('Middleware :: wrong return type', function () {
    Reflect::validateMiddleware(function (Request $request, callable $next): int {
        return $next($request);
    });
})->throws(TypeError::class, "Middleware's return type must implement");


test('Middleware :: wrong parameter count', function () {
    Reflect::validateMiddleware(function (Request $request): Request|Response {
        return $request;
    });
})->throws(ArgumentCountError::class, 'Middleware must accept two parameters');


test('Middleware :: wrong parameter type I', function () {
    Reflect::validateMiddleware(function (string $request, callable $next): Response|Request {
        return $next($request);
    });
})->throws(TypeError::class, "Middleware's first parameter must implement");


test('Middleware :: wrong parameter type II', function () {
    Reflect::validateMiddleware(function (Request $request, int $next): Request|Response {
        return $next($request);
    });
})->throws(TypeError::class, "Middleware's second parameter must be of type");
