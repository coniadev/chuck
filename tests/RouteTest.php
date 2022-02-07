<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Testing\Request;
use Chuck\Route;

uses(TestCase::class);


test('Route matching', function () {
    $route = Route::get('hans', '/chuck', fn () => null);

    $request = $this->request(method: 'GET', url: '/chuck');
    expect($route->match($request))->toBe($route);

    $request = $this->request(method: 'GET', url: '/rick');
    expect($route->match($request))->toBe(null);
});
