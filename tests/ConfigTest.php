<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\{DatabaseCase, C};
use Conia\Chuck\Tests\Fixtures\TestRenderer;
use Conia\Chuck\Config;
use Conia\Chuck\Config\Connection;
use Conia\Chuck\Logger;

uses(DatabaseCase::class);


test('Defaults', function () {
    $config = new Config('chuck');

    expect($config->app())->toBe('chuck');
});


test('Wrong app name', function () {
    new Config('wrong name');
})->throws(ValueError::class, 'app name');


test('Custom options', function () {
    $config = new Config('chuck');
    $config->set('album', 'Symbolic');

    expect($config->has('album'))->toBe(true);
    expect($config->get('album'))->toBe('Symbolic');
});


test('Default value', function () {
    $config = new Config('chuck');

    expect($config->get('missing', 'default'))->toBe('default');
});


test('Missing key', function () {
    $config = new Config('chuck');

    $config->get('missing');
})->throws(InvalidArgumentException::class, 'does not exist');


test('Logger setup', function () {
    $config = new Config('chuck');
    $config->setupLogger(function () {
        $logfile = C::root() . C::DS . 'log' . C::DS . bin2hex(random_bytes(4)) . '.log';
        return new Logger(Logger::DEBUG, $logfile);
    });

    expect($config->logger())->toBeInstanceOf(Logger::class);
    // fetches the memoized logger
    expect($config->logger())->toBeInstanceOf(Logger::class);
});


test('Logger call without setup', function () {
    $config = new Config('chuck');

    expect($config->logger())->toBe(null);
});


test('Add renderer', function () {
    $config = new Config('chuck');
    $config->addRenderer('test', TestRenderer::class);
    $renderer = $config->renderer($this->request(), 'test');

    expect($renderer)->toBeInstanceOf(TestRenderer::class);
});


test('Add wrong renderer', function () {
    $config = new Config('chuck');
    $config->addRenderer('test', Config::class);
})->throws(ValueError::class, 'must extend');


test('Add database connection', function () {
    $config = new Config('chuck');
    $conn1 = new Connection($this->getDsn(), $this->getSqlDirs());
    $config->addConnection($conn1);
    $conn2 = new Connection($this->getDsn(), $this->getSqlDirs());
    $config->addConnection($conn2, name: 'second');

    expect($config->connection())->toBe($conn1);
    expect($config->connection('second'))->toBe($conn2);
});


test('Add duplicate database connection', function () {
    $config = new Config('chuck');
    $conn1 = new Connection($this->getDsn(), $this->getSqlDirs());
    $config->addConnection($conn1);
    $conn2 = new Connection($this->getDsn(), $this->getSqlDirs());
    $config->addConnection($conn2);
})->throws(ValueError::class, 'already exists');



test('Scripts', function () {
    $config = new Config('chuck');
    $scripts = $config->scripts();

    expect(count($scripts->get()))->toBe(1);
    expect($scripts->get()[0])->toEndWith('/bin');

    $scripts->add(C::root() . C::DS . 'scripts');

    expect(count($scripts->get()))->toBe(2);
    expect($scripts->get()[0])->toEndWith(C::root() . C::DS . 'scripts');
    expect($scripts->get()[1])->toEndWith('/bin');
});
