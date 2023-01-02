<?php

declare(strict_types=1);

use Conia\Chuck\Error\ValueError;
use Conia\Chuck\Response\Headers;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Set header', function () {
    $headers = new Headers([
        ['header-value', 'value', false],
        ['SECOND-VALUE', 'value', true]
    ]);

    expect($headers->has('Header-Value'))->toBe(true);
    expect($headers->has('seconD-VALue'))->toBe(true);
});


test('Set header replace false', function () {
    $headers = new Headers();
    $headers->add('header-value', 'value', false);
    $headers->add('header-value', 'value2', false);


    expect($headers->has('Header-Value'))->toBe(true);
    expect(count($headers->list()['Header-Value']['value']))->toBe(2);
});


test('Set invalid header', function () {
    new Headers([['wrong header', 'value']]);
})->throws(ValueError::class);


test('Emit defaults', function () {
    $headers = new Headers();
    $headers->emit();

    expect($headers->emitted())->toBe([
        'Content-Type: text/html; charset=UTF-8',
        'HTTP/1.1 200 OK',
    ]);
});


test('Emit values', function () {
    $headers = new Headers([
        ['header-value', 'value', true],
        ['SECOND-VALUE', 'value', false],
    ]);
    $headers->add('content-TYPE', 'text/plain');
    $headers->add('Header-Value', 'second-value', false);
    $headers->add('Second-value', 'second-value', true);
    $headers->emit(404, '1.2', 'UTF-32', 'Custom Phrase');

    expect($headers->emitted())->toBe([
        'Header-Value: value',
        'Header-Value: second-value',
        'Second-Value: second-value',
        'Content-Type: text/plain; charset=UTF-32',
        'HTTP/1.2 404 Custom Phrase',
    ]);
});


test('Content-Type', function () {
    $headers = new Headers();
    $headers->emit();
    expect($headers->emitted()[0])->toBe('Content-Type: text/html; charset=UTF-8');

    $headers = new Headers();
    $headers->add('content-TYPE', 'text/plain');
    $headers->emit();
    expect($headers->emitted()[0])->toBe('Content-Type: text/plain; charset=UTF-8');

    $headers = new Headers();
    $headers->add('content-TYPE', 'text/plain; charset=UTF-16');
    $headers->emit(charset: 'UTF-32');
    expect($headers->emitted()[0])->toBe('Content-Type: text/plain; charset=UTF-16');

    $headers = new Headers();
    $headers->add('content-type', 'application/json');
    $headers->emit(charset: 'UTF-16');
    expect($headers->emitted()[0])->toBe('Content-Type: application/json');
});
