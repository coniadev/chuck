<?php

declare(strict_types=1);

use Chuck\App;
use Chuck\Routing\Route;
use Chuck\SessionInterface;
use Chuck\Middleware\Session;
use Chuck\Tests\TestCase;

uses(TestCase::class);


test('Session middleware', function () {
    $app = App::create($this->options());
    $app->add(Route::get('index', '/', 'Chuck\Tests\Fix\TestController::textView'));
    $app->middleware(new Session());
    ob_start();
    $app->run();
    ob_end_clean();
    $request = $app->request();

    expect($request->session())->toBeInstanceOf(SessionInterface::class);
});
