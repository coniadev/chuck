<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Template;

uses(TestCase::class);


test('Simple rendering', function () {
    $config = $this->config();
    $tpl = new Template($config->templates(), ['config' => $config]);

    expect($tpl->render('default:index', ['text' => 'rules']))->toBe("<h1>chuck</h1>\n<p>rules</p>\n");
});


test('Exists helper', function () {
    $tpl = new Template($this->config()->templates());

    expect($tpl->exists('default:index'))->toBe(true);
    expect($tpl->exists('default:wrongindex'))->toBe(false);
});


test('Config error :: nonexistent template dir', function () {
    new Template($this->config(['templates' => __DIR__ . '/Fixtures/fantasy/path'])->templates());
})->throws(\ValueError::class, 'Template directory does not exists');


test('Config error :: outside root', function () {
    new Template($this->config(['templates' => __DIR__ . '../../../etc'])->templates());
})->throws(\ValueError::class, 'paths must be inside the root directory');


test('Config error :: wrong template format I', function () {
    $tpl = new Template($this->config()->templates());

    $tpl->render('default:sub:index');
})->throws(\ValueError::class, 'Invalid template format');


test('Config error :: wrong template format II', function () {
    $tpl = new Template($this->config()->templates());

    $tpl->render('');
})->throws(\InvalidArgumentException::class, 'No template');


test('Render error :: missing template', function () {
    $tpl = new Template($this->config()->templates());

    $tpl->render('nonexistent');
})->throws(\ValueError::class, 'inside the project root');


test('Render error :: template outside root directory', function () {
    $tpl = new Template($this->config()->templates());

    $tpl->render('../../../../../etc/passwd');
})->throws(\ValueError::class, 'inside the project root');


test('Render error :: parse error', function () {
    $tpl = new Template($this->config()->templates());

    $tpl->render('failing');
})->throws(\ParseError::class);
