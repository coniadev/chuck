<?php

declare(strict_types=1);

use Chuck\Body\{Text, Json, File};
use Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Json', function () {
    $body = new Json(['name' => 'Chuck', 'count' => 3]);


    ob_start();
    $body->emit();
    $content = ob_get_contents();
    ob_end_clean();

    expect($content)->toBe('{"name":"Chuck","count":3}');
    expect((string)$body)->toBe('{"name":"Chuck","count":3}');
});


test('Text', function () {
    $body = new Text('Individual Thought Patterns');


    ob_start();
    $body->emit();
    $content = ob_get_contents();
    ob_end_clean();

    expect($content)->toBe('Individual Thought Patterns');
    expect((string)$body)->toBe('Individual Thought Patterns');
});
