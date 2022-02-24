<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Util\Reflect;
use Chuck\{Request, Response};

uses(TestCase::class);


test('Middleware :: no return type', function () {
    Reflect::validateMiddleware(function (Request $request, callable $next) {
        return $next($request);
    });
})->throws(\InvalidArgumentException::class, 'Middleware return type must be given');


test('Middleware :: wrong return type', function () {
    Reflect::validateMiddleware(function (Request $request, callable $next): int {
        return $next($request);
    });
})->throws(\InvalidArgumentException::class, "Middleware's return type must implement");


test('Middleware :: wrong parameter count', function () {
    Reflect::validateMiddleware(function (Request $request): Request|Response {
        return $request;
    });
})->throws(\InvalidArgumentException::class, 'Middleware must accept two parameters');


test('Middleware :: wrong parameter type I', function () {
    Reflect::validateMiddleware(function (string $request, callable $next): Response|Request {
        return $next($request);
    });
})->throws(\InvalidArgumentException::class, "Middleware's first parameter must implement");


test('Middleware :: wrong parameter type II', function () {
    Reflect::validateMiddleware(function (Request $request, int $next): Request|Response {
        return $next($request);
    });
})->throws(\InvalidArgumentException::class, "Middleware's second parameter must be of type");
