<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\{App, Router, Route};

uses(TestCase::class);


test('Create helper', function () {
    expect(App::create($this->getConfigArray()))->toBeInstanceOf(App::class);
});


test('App init', function () {
    $app = new App($this->request(method: 'GET', url: '/'));
    $app->route(Route::get('index', '/', 'Chuck\Tests\Controller::view'));
    $app->run();
});
