<?php

declare(strict_types=1);

use Chuck\App;
use Chuck\Route;
use Chuck\SessionInterface;
use Chuck\Middleware\Session;
use Chuck\Tests\TestCase;

uses(TestCase::class);


test('Session middleware', function () {
    $app = App::create($this->options());
    $app->route(Route::get('index', '/', 'Chuck\Tests\Fix\TestController::textView'));
    $app->middleware(new Session());
    $app->run();
    $request = $app->request();

    expect($request->session())->toBeInstanceOf(SessionInterface::class);
});
