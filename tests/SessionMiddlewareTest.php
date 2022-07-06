<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\SessionInterface;
use Conia\Chuck\Middleware\Session;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Session middleware', function () {
    $app = App::create($this->config());
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::textView');
    $app->middleware(new Session($this->request()->config()->app()));
    ob_start();
    $app->run();
    ob_end_clean();
    $request = $app->request();

    expect($request->session())->toBeInstanceOf(SessionInterface::class);
});
