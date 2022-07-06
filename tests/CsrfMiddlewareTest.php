<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\CsrfInterface;
use Conia\Chuck\Middleware\Csrf;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Csrf middleware', function () {
    $app = App::create($this->config());
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    $app->middleware(new Csrf());
    ob_start();
    $app->run();
    ob_end_clean();
    $request = $app->request();

    expect($request->csrf())->toBeInstanceOf(CsrfInterface::class);
});
