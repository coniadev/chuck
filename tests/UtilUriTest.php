<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\Util\Uri;

uses(TestCase::class);


test('Uri host', function () {
    expect(Uri::host())->toBe('www.example.com');
});


test('Uri scheme', function () {
    expect(Uri::scheme())->toBe('http');
    $this->enableHttps();
    expect(Uri::scheme())->toBe('https');
    $this->disableHttps();
    expect(Uri::scheme())->toBe('http');
    expect(isset($_SERVER['REQUEST_SCHEME']))->toBe(false);
    $this->enableHttps('REQUEST_SCHEME');
    expect(Uri::scheme())->toBe('https');
    expect(isset($_SERVER['REQUEST_SCHEME']))->toBe(true);
    $this->disableHttps();
    expect(Uri::scheme())->toBe('http');
    $this->enableHttps('HTTP_X_FORWARDED_PROTO');
    expect(Uri::scheme())->toBe('https');
    expect(isset($_SERVER['HTTP_X_FORWARDED_PROTO']))->toBe(true);
    $this->disableHttps();
});


test('Uri origin', function () {
    expect(Uri::origin())->toBe('http://www.example.com');
    $this->enableHttps();
    expect(Uri::origin())->toBe('https://www.example.com');
    $this->disableHttps();
    expect(Uri::origin())->toBe('http://www.example.com');
});


test('Uri origin failing', function () {
    $_SERVER['HTTP_HOST'] = '££££@@@@~~~';
    $thrown = false;

    try {
        Uri::origin();
    } catch (ValueError $e) {
        if ($e->getMessage() === 'Invalid origin') {
            $thrown = true;
        }
    }

    unset($_SERVER['HTTP_HOST']);
    expect($thrown)->toBe(true);
});


test('Uri path', function () {
    $this->setRequestUri('/albums?from=1988&to=1991');

    expect(Uri::path())->toBe('/albums?from=1988&to=1991');
    expect(Uri::path(stripQuery: true))->toBe('/albums');
});


test('Uri failing path I', function () {
    unset($_SERVER['REQUEST_URI']);
    Uri::path();
})->throws(ValueError::class, 'Unable to read path');


test('Uri failing path II', function () {
    $this->setRequestUri(' /%%%%%   ');
    Uri::path();
})->throws(ValueError::class, 'Invalid path');


test('Uri url', function () {
    $this->setRequestUri('/albums?from=1988&to=1991');

    expect(Uri::url())->toBe('http://www.example.com/albums?from=1988&to=1991');
    expect(Uri::url(stripQuery: true))->toBe('http://www.example.com/albums');
});
