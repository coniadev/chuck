<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Template;

uses(TestCase::class);


test('Simple rendering', function () {
    $config = $this->config();
    $tpl = new Template($this->request(config: $config), ['config' => $config]);

    expect($tpl->render('default:index', ['text' => 'rules']))->toBe("<h1>chuck</h1>\n<p>rules</p>\n");
});


test('Exists helper', function () {
    $tpl = new Template($this->request());

    expect($tpl->exists('default:index'))->toBe(true);
    expect($tpl->exists('default:wrongindex'))->toBe(false);
});


test('Config error :: nonexistent template dir', function () {
    new Template($this->request(options: ['templates.default' => __DIR__ . '/Fixtures/fantasy/path']));
})->throws(\ValueError::class, 'Template directory does not exists');


test('Config error :: outside root', function () {
    new Template($this->request(options: ['templates.default' => __DIR__ . '../../../etc']));
})->throws(\ValueError::class, 'paths must be inside the root directory');


test('Config error :: wrong template format I', function () {
    $tpl = new Template($this->request());

    $tpl->render('default:sub:index');
})->throws(\ValueError::class, 'Invalid template format');


test('Config error :: wrong template format II', function () {
    $tpl = new Template($this->request());

    $tpl->render('');
})->throws(\InvalidArgumentException::class, 'No template');


test('Render error :: missing template', function () {
    $tpl = new Template($this->request());

    $tpl->render('nonexistent');
})->throws(\ValueError::class, 'inside the project root');


test('Render error :: template outside root directory', function () {
    $tpl = new Template($this->request());

    $tpl->render('../../../../../etc/passwd');
})->throws(\ValueError::class, 'inside the project root');


test('Render error :: parse error', function () {
    $tpl = new Template($this->request());

    $tpl->render('failing');
})->throws(\ParseError::class);
