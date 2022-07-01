<?php

declare(strict_types=1);

use Chuck\Error\{InvalidTemplateFormat, TemplateNotFound};
use Chuck\Tests\Setup\TestCase;
use Chuck\Template\{Engine, Template};

uses(TestCase::class);


test('Simple rendering', function () {
    $tpl = new Engine($this->templates(), ['config' => $this->config()]);

    expect(
        $this->fullTrim($tpl->render('simple', ['text' => 'rocks']))
    )->toBe('<h1>chuck</h1><p>rocks</p>');
});


test('Simple rendering (namespaced)', function () {
    $tpl = new Engine($this->namespacedTemplates(), ['config' => $this->config()]);

    expect(
        $this->fullTrim($tpl->render('namespace:simple', ['text' => 'rocks']))
    )->toBe('<h1>chuck</h1><p>rocks</p>');
});


test('Extension given', function () {
    $tpl = new Engine($this->templates(), ['config' => $this->config()]);

    expect($this->fullTrim($tpl->render('extension.tpl')))->toBe('<p></p>');
});


test('Non string rendering', function () {
    $tpl = new Engine($this->templates());

    expect($this->fullTrim($tpl->render('nonstring', [
        'request' => $this->request(url: '/albums')
    ])))->toBe('<p>/albums</p>');
});


test('Raw rendering', function () {
    $tpl = new Engine($this->templates());

    expect($tpl->render('raw', [
        'html' => '<b>chuck</b>',
    ]))->toBe("&lt;b&gt;chuck&lt;/b&gt;<b>chuck</b>");
});


test('Raw rendering with Stringable', function () {
    $tpl = new Engine($this->templates());

    expect($tpl->render('raw', [
        'html' => new class()
        {
            public function __toString(): string
            {
                return '<b>chuck</b>';
            }
        },
    ]))->toBe("&lt;b&gt;chuck&lt;/b&gt;<b>chuck</b>");
});


test('Clean rendering', function () {
    $tpl = new Engine($this->templates());

    expect($tpl->render('clean', [
        'html' => '<script src="/evil.js"></script><b>chuck</b>',
    ]))->toBe("<b>chuck</b>");
});


test('Array rendering', function () {
    $tpl = new Engine($this->templates());

    expect(trim($tpl->render('iter', [
        'arr' => ['<b>1</b>', '<b>2</b>', '<b>3</b>']
    ])))->toBe('&lt;b&gt;1&lt;/b&gt;&lt;b&gt;2&lt;/b&gt;&lt;b&gt;3&lt;/b&gt;');
});


test('Helper function rendering', function () {
    $tpl = new Engine($this->templates(), ['config' => $this->config()]);

    expect($this->fullTrim($tpl->render('helper')))->toBe(
        '&lt;script&gt;&lt;script&gt;<b>clean</b>'
    );
});


test('Empty helper method', function () {
    $tpl = new Engine($this->templates());

    expect($this->fullTrim($tpl->render('empty', [
        'empty' => '',
        'notempty' => '<b>not empty</b>',
    ])))->toBe('&lt;b&gt;not empty&lt;/b&gt;');
});


test('Iterator rendering', function () {
    $tpl = new Engine($this->templates());

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
        $this->templates(),
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


test('Multilple layout error', function () {
    (new Engine($this->templates()))->render('multilayout');
})->throws(RuntimeException::class, 'layout already set');


test('Get nonexistent layout error', function () {
    $engine = new Engine($this->templates());
    (new Template($engine, 'moniker', []))->getLayout('nonexistent');
})->throws(RuntimeException::class, 'layout not set');


test('Section rendering', function () {
    $tpl = new Engine($this->templates());

    expect($this->fullTrim($tpl->render('addsection', [
        'text' => 'chuck'
    ])))->toBe('<div><p>chuck</p>chuck</div><ul><li>chuck</li></ul>');
});


test('Missing section rendering', function () {
    $tpl = new Engine($this->templates());

    expect($this->fullTrim($tpl->render('nosection', [
        'text' => 'chuck'
    ])))->toBe('<div><p>chuck</p>chuck</div><p>no list</p>');
});


test('Insert rendering', function () {
    $tpl = new Engine($this->templates());

    expect($this->fullTrim($tpl->render('insert', [
        'text' => 'Chuck'
    ])))->toBe('<p>Chuck</p><p>Schuldiner</p>');
});


test('Exists helper', function () {
    $tpl = new Engine($this->templates());

    expect($tpl->exists('simple'))->toBe(true);
    expect($tpl->exists('wrongindex'))->toBe(false);
});


test('Config error :: wrong template format I', function () {
    $tpl = new Engine($this->templates());

    $tpl->render('default:sub:index');
})->throws(InvalidTemplateFormat::class, 'Invalid template format');


test('Config error :: wrong template format II', function () {
    $tpl = new Engine($this->templates());

    $tpl->render('');
})->throws(InvalidArgumentException::class, 'No template');


test('Render error :: missing template', function () {
    $tpl = new Engine($this->templates());

    $tpl->render('nonexistent');
})->throws(TemplateNotFound::class, 'not found');


test('Render error :: template outside root directory', function () {
    $tpl = new Engine($this->templates());

    $tpl->render('../../../../../etc/passwd');
})->throws(TemplateNotFound::class, 'not found');


test('Render error :: parse error', function () {
    $tpl = new Engine($this->templates());

    $tpl->render('failing');
})->throws(ParseError::class);
