<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Template\Template;

uses(TestCase::class);


test('Simple rendering', function () {
    $config = $this->config();
    $tpl = new Template($config->templates(), ['config' => $config]);

    expect($tpl->render('index', ['text' => 'rules']))->toBe("<h1>chuck</h1>\n<p>rules</p>\n");
});


test('Non string rendering', function () {
    $config = $this->config();
    $tpl = new Template($config->templates());

    expect($tpl->render('nonstring', [
        'request' => $this->request(url: '/albums')
    ]))->toBe("<p>/albums</p>\n");
});


test('Raw rendering', function () {
    $config = $this->config();
    $tpl = new Template($config->templates());

    expect($tpl->render('raw', [
        'html' => '<b>chuck</b>',
    ]))->toBe("&lt;b&gt;chuck&lt;/b&gt;<b>chuck</b>");
});


test('Clean rendering', function () {
    $config = $this->config();
    $tpl = new Template($config->templates());

    expect($tpl->render('clean', [
        'html' => '<script src="/evil.js"></script><b>chuck</b>',
    ]))->toBe("<strong>chuck</strong>");
});


test('Exists helper', function () {
    $tpl = new Template($this->config()->templates());

    expect($tpl->exists('index'))->toBe(true);
    expect($tpl->exists('wrongindex'))->toBe(false);
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
