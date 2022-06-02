<?php

declare(strict_types=1);

use Chuck\App;
use Chuck\Routing\Route;
use Chuck\Logger;
use Chuck\Middleware\Logging;
use Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Logging middleware', function () {
    $app = App::create($this->config());
    $app->add(Route::get('index', '/', 'Chuck\Tests\Fixtures\TestController::textView'));
    $app->middleware(new Logging());
    ob_start();
    $app->run();
    ob_end_clean();
    $request = $app->request();

    expect($request->logger())->toBeInstanceOf(Logger::class);
});
