<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\Util\Http;

uses(TestCase::class);


test('Http origin', function () {
    expect(Http::origin())->toBe('http://www.example.com');
    $this->enableHttps();
    expect(Http::origin())->toBe('https://www.example.com');
    $this->setPort(666);
    expect(Http::origin())->toBe('https://www.example.com:666');
    $this->disableHttps();
    $this->setPort('');
    expect(Http::origin())->toBe('http://www.example.com');
});


test('Http origin failing', function () {
    $_SERVER['HTTP_HOST'] = '££££@@@@~~~';
    $thrown = false;

    try {
        Http::origin();
    } catch (ValueError $e) {
        if ($e->getMessage() === 'Invalid origin') {
            $thrown = true;
        }
    }

    unset($_SERVER['HTTP_HOST']);
    expect($thrown)->toBe(true);
});