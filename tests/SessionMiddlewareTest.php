<?php

declare(strict_types=1);

use Chuck\App;
use Chuck\Routing\Route;
use Chuck\SessionInterface;
use Chuck\Middleware\Session;
use Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Session middleware', function () {
    $app = App::create($this->config());
    $app->route(Route::get('/', 'Chuck\Tests\Fixtures\TestController::textView'));
    $app->middleware(new Session($this->request()->config()->app()));
    ob_start();
    $app->run();
    ob_end_clean();
    $request = $app->request();

    expect($request->session())->toBeInstanceOf(SessionInterface::class);
});
