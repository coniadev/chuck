<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, Helper};
use Chuck\Memcached\Memcached;

uses(TestCase::class);

const prefix = '___CHUCK__TEST___';


test('Memcached connection', function () {
    $mc = new Memcached();

    expect($mc->getConn())->toBeInstanceOf(Memcached::class);
})->skip(!Helper::memcachedExtensionLoaded());


test('Memcached connection from config', function () {
    $options = [
        'memcached.host' => 'localhost',
        'memcached.port' => 11211,
        'memcached.expire' => 666,
    ];
    $mc = Memcached::fromConfig($this->config($options));
    expect($mc->getConn())->toBeInstanceOf(\Memcached::class);
    expect($mc->getExpire(null))->toBe(666);

    $options['memcached.implementation'] = 'Memcached';
    $mc = Memcached::fromConfig($this->config($options));
    expect($mc->getConn())->toBeInstanceOf(\Memcached::class);
    expect($mc->getExpire(null))->toBe(666);
})->skip(!Helper::memcachedExtensionLoaded());


test('Memcached Set key', function () {
    $mc = new Memcached();

    expect($mc->set(prefix . 'founder', 'Chuck Schuldiner', 1))->toBe(true);
})->skip(!Helper::memcachedExtensionLoaded());


test('Memcached Add key', function () {
    $mc = new Memcached();

    expect($mc->add(prefix . 'drums', 'Gene Hoglan', 1))->toBe(true);
    expect($mc->add(prefix . 'drums', 'Gene Hoglan', 1))->toBe(false);
})->skip(!Helper::memcachedExtensionLoaded());


test('Memcached Get key', function () {
    $mc = new Memcached();
    $mc->set(prefix . 'guitar', 'Paul Masdival', 1);

    expect($mc->get(prefix . 'guitar'))->toBe('Paul Masdival');
})->skip(!Helper::memcachedExtensionLoaded());


test('Memcached Delete key', function () {
    $mc = new Memcached();
    $mc->set(prefix . 'bass', 'Steve DiGiorgio', 1);
    expect($mc->get(prefix . 'bass'))->toBe('Steve DiGiorgio');
    $mc->delete(prefix . 'bass');
    expect($mc->get(prefix . 'bass'))->toBe(false);
})->skip(!Helper::memcachedExtensionLoaded());


test('Memcache connection', function () {
    $mc = new Memcached(implementation: 'Memcache');
    expect($mc->getConn())->toBeInstanceOf(\Memcache::class);

    $mc = new Memcached(preferMemcached: false);
    expect($mc->getConn())->toBeInstanceOf(\Memcache::class);
})->skip(!Helper::memcacheExtensionLoaded());


test('Memcache connection from config', function () {
    $options = [
        'memcached.implementation' => 'Memcache',
        'memcached.host' => 'localhost',
        'memcached.port' => 11211,
        'memcached.expire' => 666,
    ];
    $mc = Memcached::fromConfig($this->config($options));
    expect($mc->getConn())->toBeInstanceOf(\Memcache::class);
    expect($mc->getExpire(null))->toBe(666);
})->skip(!Helper::memcacheExtensionLoaded());


test('Memcache Set key', function () {
    $mc = new Memcached(implementation: 'Memcache');

    expect($mc->set(prefix . '_founder', 'Chuck Schuldiner', 1))->toBe(true);
})->skip(!Helper::memcacheExtensionLoaded());


test('Memcache Add key', function () {
    $mc = new Memcached(implementation: 'Memcache');

    expect($mc->add(prefix . '_drums', 'Gene Hoglan', 1))->toBe(true);
    expect($mc->add(prefix . '_drums', 'Gene Hoglan', 1))->toBe(false);
})->skip(!Helper::memcacheExtensionLoaded());


test('Memcache Get key', function () {
    $mc = new Memcached(implementation: 'Memcache');
    $mc->set(prefix . '_guitar', 'Paul Masdival', 1);

    expect($mc->get(prefix . '_guitar'))->toBe('Paul Masdival');
})->skip(!Helper::memcacheExtensionLoaded());


test('Memcache Delete key', function () {
    $mc = new Memcached(implementation: 'Memcache');
    $mc->set(prefix . '_bass', 'Steve DiGiorgio', 1);
    expect($mc->get(prefix . '_bass'))->toBe('Steve DiGiorgio');
    $mc->delete(prefix . '_bass');
    expect($mc->get(prefix . '_bass'))->toBe(false);
})->skip(!Helper::memcacheExtensionLoaded());
