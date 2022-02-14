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
    $app->route(Route::get('index', '/', 'Chuck\Tests\Controller::textView'));
    ob_start();
    $response = $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('success');
    expect(in_array('Content-Type: text/html; charset=UTF-8', $response->headersList()))->toBe(true);
    expect(in_array('HTTP/1.1 200', $response->headersList()))->toBe(true);
});
