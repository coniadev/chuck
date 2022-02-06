<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\App;
use Chuck\Request;

uses(TestCase::class);


test('Parse floats', function () {
    $app = new App($this->getConfig());

    $app->get('index', '/hans/franz', 'Class::method');
    $app->get('index', '/hans/franz', function (Request $request) {
    });
    $app->route('index', '/hans/franz', 'Class::method');
});


class Hans extends Controller
{
    public function __construct(protected Request $request)
    {
    }

    #[View(permission: 'hans', method: ['get', 'post'], render = 'json')]
    public function index()
    {
    }
}
