<?php

declare(strict_types=1);

use Chuck\App;
use Chuck\CsrfInterface;
use Chuck\Middleware\Csrf;
use Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Csrf middleware', function () {
    $app = App::create($this->config());
    $app->route('/', 'Chuck\Tests\Fixtures\TestController::textView');
    $app->middleware(new Csrf());
    ob_start();
    $app->run();
    ob_end_clean();
    $request = $app->request();

    expect($request->csrf())->toBeInstanceOf(CsrfInterface::class);
});
