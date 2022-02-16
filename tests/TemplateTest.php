<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Template;

uses(TestCase::class);


test('Simple rendering', function () {
    $tpl = new Template($this->request());

    expect($tpl->render('default::index'))->toBe("<h1>chuck</h1>\n");
});


test('Config error :: nonexistent template dir', function () {
    new Template($this->request(options: ['templates.default' => __DIR__ . '/fantasy/path']));
})->throws(\ValueError::class);


test('Config error :: outside root', function () {
    new Template($this->request(options: ['templates.default' => __DIR__ . '../../../etc']));
})->throws(\ValueError::class);


test('Config error :: wrong template format I', function () {
    $tpl = new Template($this->request());

    $tpl->render('default:index');
})->throws(\ValueError::class);


test('Config error :: wrong template format II', function () {
    $tpl = new Template($this->request());

    $tpl->render('default::');
})->throws(\ValueError::class);


test('Render error :: missing template', function () {
    $tpl = new Template($this->request());

    $tpl->render('default::nonexistent');
})->throws(\ValueError::class);


test('Render error :: template outside root directory', function () {
    $tpl = new Template($this->request());

    $tpl->render('default::../../../../../etc/passwd');
})->throws(\ValueError::class);


test('Render error :: parse error', function () {
    $tpl = new Template($this->request());

    $tpl->render('default::failing');
})->throws(\ParseError::class);
