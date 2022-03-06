<?php

declare(strict_types=1);

use Chuck\Tests\Setup\{TestCase, C};
use Chuck\Config;

uses(TestCase::class);


test('Defaults', function () {
    $config = new Config($this->minimalOptions());

    expect($config->get('app'))->toBe('chuck');
    expect($config->path->root)->toBe(C::root());
    expect($config->path()->root)->toBe(C::root());
});


test('App name/id not set', function () {
    new Config([]);
})->throws(ValueError::class, "The 'app' setting must exist");


test('Root path not set', function () {
    new Config(['app' => 'chuck']);
})->throws(ValueError::class, 'path not set');


test('Root path not absolute', function () {
    new Config($this->options(['path.root' => 'no/absolute/path']));
})->throws(ValueError::class, 'must be an absolute');


test('Public not determinable', function () {
    new Config($this->options([
        'path.root' => C::root() . C::DS . 'altroot'
    ]));
})->throws(ValueError::class, 'not be determined');


test('Public set', function () {
    $config = new Config([
        'app' => 'chuck',
        'path.root' => C::root() . C::DS . 'altroot',
        'path.public' => 'www'
    ]);

    expect($config->path->public)->toBe(realpath(
        C::root() . C::DS . 'altroot' . C::DS . 'www'
    ));
});


test('Custom options', function () {
    $config = new Config($this->options([
        'album' => 'Symbolic',
    ]));

    expect($config->get('app'))->toBe('chuck');
    expect($config->app())->toBe('chuck');
    expect($config->get('album'))->toBe('Symbolic');
});


test('Host and origin', function () {
    $config = new Config($this->minimalOptions());

    expect($config->get('origin'))->toBe('http://www.example.com');
    expect($config->get('host'))->toBe('www.example.com');

    $this->enableHttps();
    $config = new Config($this->minimalOptions());

    expect($config->get('origin'))->toBe('https://www.example.com');
});


test('Default value', function () {
    $config = new Config($this->minimalOptions());

    expect($config->get('missing', 'default'))->toBe('default');
});


test('Missing key', function () {
    $config = new Config($this->minimalOptions());

    $config->get('missing');
})->throws(InvalidArgumentException::class, 'does not exist');


test('Additional path', function () {
    $config = new Config($this->options([
        'path.anotherone' => 'templates',
    ]));
    $compare = C::root() . C::DS . 'templates';

    expect($config->path->get('anotherone'))->toBe($compare);
});


test('List of paths', function () {
    $config = new Config($this->options([
        'path.list' => ['templates', 'sql'],
    ]));
    $prefix = C::root() . C::DS;
    $compare = [$prefix . 'templates', $prefix . 'sql'];

    expect($config->path->list('list'))->toBe($compare);
});


test('List of paths wrong method', function () {
    $config = new Config($this->options([
        'path.list' => ['templates', 'sql'],
    ]));

    $config->path->get('list');
})->throws(InvalidArgumentException::class, 'contains a list');


test('Single path wrong method', function () {
    $config = new Config($this->options([
        'path.single' => 'templates',
    ]));

    $config->path->list('single');
})->throws(InvalidArgumentException::class, 'contains a single');


test('Wrong path', function () {
    $config = new Config($this->options());

    $config->path->get('anotherone');
})->throws(InvalidArgumentException::class, 'not present');


test('Wrong paths', function () {
    $config = new Config($this->options());

    $config->path->list('anotherone');
})->throws(InvalidArgumentException::class, 'not present');


test('Wrong path results default', function () {
    $config = new Config($this->options());

    expect($config->path->get('anotherone', ''))->toBe('');
});


test('Wrong paths results in empty array', function () {
    $config = new Config($this->options());

    expect($config->path->list('anotherone', []))->toBe([]);
});


test('Template paths', function () {
    $config = new Config($this->options([
        // templates.default is defined in $this->options()
        'templates.relative' => 'templates/additional',
    ]));
    $prefix = C::root() . C::DS . 'templates' . C::DS;

    expect($config->templates()['default'])->toBe($prefix . 'default');
    expect($config->templates()['relative'])->toBe($prefix . 'additional');
});


test('Migrations paths', function () {
    // NOTICE: we're reusing the existing template paths for the test
    $config = new Config($this->options([
        'migrations' => C::root() . C::DS . 'migrations',
        'migrations.relative' => 'templates' . C::DS . 'additional',
    ]));
    $prefix = C::root() . C::DS;

    expect($config->migrations())->toBe([
        $prefix . 'migrations',
        $prefix . 'templates' . C::DS . 'additional',
    ]);
});


test('Script paths', function () {
    $config = new Config($this->options([
        'scripts' => C::root() . C::DS . 'scripts' . C::DS . 'default',
        'scripts.relative' => 'scripts' . C::DS . 'additional',
    ]));
    $prefix = C::root() . C::DS . 'scripts' . C::DS;

    expect($config->scripts())->toBe([
        $prefix . 'default',
        $prefix . 'additional',
    ]);
});


test('SQL paths', function () {
    $prefix = C::root() . C::DS . 'sql' . C::DS;
    $config = new Config($this->options([
        'db' => ['dsn' => 'sqlite:...'],
        'sql' => [
            'all' => $prefix . 'default',
            'sqlite' => $prefix . 'sqlite',
        ],
        'sql.relative' => 'sql' . C::DS . 'additional',
    ]));

    expect($config->db('default', 'default')->sqlDirs)->toBe([
        $prefix . 'sqlite',
        $prefix . 'default',
    ]);

    expect($config->db('default', 'relative')->sqlDirs)->toBe([
        $prefix . 'additional',
    ]);
});


test('Log file creation', function () {
    $logfile = C::root() . C::DS . 'log' . C::DS . bin2hex(random_bytes(4)) . '.log';
    $config = new Config($this->options(['log.file' => $logfile]));

    expect($config->log()->file)->toBe($logfile);
    expect(is_file($config->log()->file))->toBe(true);

    @unlink($logfile);
});


test('Log file not writeable', function () {
    $logfile = C::root() . C::DS . 'log' . C::DS . bin2hex(random_bytes(4)) . '.log';
    touch($logfile);
    chmod($logfile, 0400);
    $thrown = false;

    try {
        (new Config($this->options(['log.file' => $logfile])))->log();
    } catch (ValueError $e) {
        if (str_contains($e->getMessage(), 'is not writable')) {
            $thrown = true;
        }
    }

    chmod($logfile, 0644);
    @unlink($logfile);

    expect($thrown)->toBe(true);
});
