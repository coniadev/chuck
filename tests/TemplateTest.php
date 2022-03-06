<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Template\Engine;

uses(TestCase::class);


test('Simple rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates(), ['config' => $config]);

    expect($tpl->render('index', ['text' => 'rules']))->toBe("<h1>chuck</h1>\n<p>rules</p>\n");
});


test('Non string rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    expect($tpl->render('nonstring', [
        'request' => $this->request(url: '/albums')
    ]))->toBe("<p>/albums</p>\n");
});


test('Raw rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    expect($tpl->render('raw', [
        'html' => '<b>chuck</b>',
    ]))->toBe("&lt;b&gt;chuck&lt;/b&gt;<b>chuck</b>");
});


test('Clean rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    expect($tpl->render('clean', [
        'html' => '<script src="/evil.js"></script><b>chuck</b>',
    ]))->toBe("<strong>chuck</strong>");
});


test('Array rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    expect(trim($tpl->render('iter', [
        'arr' => ['<b>1</b>', '<b>2</b>', '<b>3</b>']
    ])))->toBe('&lt;b&gt;1&lt;/b&gt;&lt;b&gt;2&lt;/b&gt;&lt;b&gt;3&lt;/b&gt;');
});


test('Iterator rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    $iter = function () {
        $a = ['<b>2</b>', '<b>3</b>', '<b>4</b>'];
        foreach ($a as $i) {
            yield $i;
        }
    };

    expect(trim($tpl->render('iter', [
        'arr' => $iter()
    ])))->toBe('&lt;b&gt;2&lt;/b&gt;&lt;b&gt;3&lt;/b&gt;&lt;b&gt;4&lt;/b&gt;');
});


test('Complex nested rendering', function () {
    $config = $this->config();
    $request = $this->request(url: '/albums');

    $tpl = new Engine(
        $config->templates(),
        ['config' => $config, 'request' => $request]
    );

    $iter = function () {
        $a = [13.73, "String II", 1];
        foreach ($a as $i) {
            yield $i;
        }
    };

    $context = [
        'title' => 'Chuck App',
        'headline' => 'Chuck App',
        'url' => 'https://example.com/chuck     /app    ',
        'array' => [
            '<b>sanitize</b>' => [
                1, "String", new class()
                {
                    public function __toString(): string
                    {
                        return '<p>Object</p>';
                    }
                }
            ],
            666 => $iter(),
        ],
        'html' => '<p>HTML</p>',
    ];
    $result = $this->fullTrim($tpl->render('complex', $context));
    $compare = '<!DOCTYPE html><html lang="en"><head><title>Chuck App</title><link rel="stylesheet" ' .
        'href="https://example.com/chuck/app"><link rel=“canonical“ href=“/albums“ /><meta name="keywords" ' .
        'content="chuck"></head><body><h1>Chuck App</h1><table><tr><td>&lt;b&gt;sanitize&lt;/b&gt;</td>' .
        '<td>1</td><td>String</td><td>&lt;p&gt;Object&lt;/p&gt;</td></tr><tr><td>666</td><td>13.73</td>' .
        '<td>String II</td><td>1</td></tr></table><p>HTML</p></body></html>';

    expect($result)->toBe($compare);
});


test('Layout rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    expect($this->fullTrim($tpl->render('uselayout', [
        'text' => 'chuck'
    ])))->toBe('<div><p>chuck</p>chuck</div>');
});


test('Section rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    expect($this->fullTrim($tpl->render('addsection', [
        'text' => 'chuck'
    ])))->toBe('<div><p>chuck</p>chuck</div><ul><li>chuck</li></ul>');
});


test('Insert rendering', function () {
    $config = $this->config();
    $tpl = new Engine($config->templates());

    expect($this->fullTrim($tpl->render('insert', [
        'text' => 'Chuck'
    ])))->toBe('<p>Chuck</p><p>Schuldiner</p>');
});


test('Exists helper', function () {
    $tpl = new Engine($this->config()->templates());

    expect($tpl->exists('index'))->toBe(true);
    expect($tpl->exists('wrongindex'))->toBe(false);
});


test('Config error :: nonexistent template dir', function () {
    new Engine($this->config(['templates' => __DIR__ . '/Fixtures/fantasy/path'])->templates());
})->throws(\ValueError::class, 'Template directory does not exists');


test('Config error :: outside root', function () {
    new Engine($this->config(['templates' => __DIR__ . '../../../etc'])->templates());
})->throws(\ValueError::class, 'paths must be inside the root directory');


test('Config error :: wrong template format I', function () {
    $tpl = new Engine($this->config()->templates());

    $tpl->render('default:sub:index');
})->throws(\ValueError::class, 'Invalid template format');


test('Config error :: wrong template format II', function () {
    $tpl = new Engine($this->config()->templates());

    $tpl->render('');
})->throws(\InvalidArgumentException::class, 'No template');


test('Render error :: missing template', function () {
    $tpl = new Engine($this->config()->templates());

    $tpl->render('nonexistent');
})->throws(\ValueError::class, 'inside the project root');


test('Render error :: template outside root directory', function () {
    $tpl = new Engine($this->config()->templates());

    $tpl->render('../../../../../etc/passwd');
})->throws(\ValueError::class, 'inside the project root');


test('Render error :: parse error', function () {
    $tpl = new Engine($this->config()->templates());

    $tpl->render('failing');
})->throws(\ParseError::class);
