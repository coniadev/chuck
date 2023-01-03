<?php

declare(strict_types=1);

use Conia\Chuck\ConfigInterface;
use Conia\Chuck\Exception\ExitException;
use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\File;
use Conia\Chuck\Renderer\{JsonRenderer, TemplateRenderer};
use Conia\Chuck\Request;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Response\ResponseInterface;
use Conia\Chuck\Response\Response;
use Conia\Chuck\Tests\Setup\{TestCase, C};

uses(TestCase::class);


test('Helper methods', function () {
    $request = $this->request();

    expect($request->config())->toBeInstanceOf(ConfigInterface::class);
    expect($request->response)->toBeInstanceOf(ResponseFactory::class);
    expect($request->response->html('Chuck'))->toBeInstanceOf(ResponseInterface::class);
    expect($request->method())->toBe('GET');
    expect($request->isMethod('GET'))->toBe(true);
    expect($request->isMethod('POST'))->toBe(false);
});


test('Url helpers', function () {
    $request = $this->request();

    expect($request->path())->toBe('/');
    expect($request->url())->toBe('http://www.example.com/');

    $this->setRequestUri('albums?from=1988&to=1991');
    expect($request->scheme())->toBe('http');
    expect($request->host())->toBe('www.example.com');
    expect($request->origin())->toBe('http://www.example.com');
    expect($request->path())->toBe('/albums?from=1988&to=1991');
    expect($request->url())->toBe('http://www.example.com/albums?from=1988&to=1991');
    expect($request->path(stripQuery: true))->toBe('/albums');
    expect($request->url(stripQuery: true))->toBe('http://www.example.com/albums');
});


test('Host helpers', function () {
    $request = $this->request();

    expect($request->host())->toBe('www.example.com');

    $save = $_SERVER['HTTP_HOST'];
    $_SERVER['HTTP_HOST'] = 'www.example.com:80';

    expect($request->host(stripPort: true))->toBe('www.example.com');
    expect($request->host())->toBe('www.example.com:80');

    $_SERVER['HTTP_HOST'] = $save;
});


test('Request::param', function () {
    $this->set('GET', ['chuck' => 'schuldiner', 'born' => '1967']);
    $this->set('POST', ['first_band' => 'Mantas']);
    $request = $this->request();

    expect($request->param('chuck'))->toBe('schuldiner');
    expect($request->param('born'))->toBe('1967');
    expect($request->param('first_band'))->toBe('Mantas');
    expect($request->param('doesnotexist', 'butthisdoes'))->toBe('butthisdoes');
});


test('Request::param failing', function () {
    $request = $this->request();

    expect($request->param('doesnotexist'))->toBe(null);
})->throws(OutOfBoundsException::class);


test('Request::params', function () {
    $this->set('GET', ['chuck' => 'schuldiner', 'born' => '1967']);
    $this->set('POST', ['first_band' => 'Mantas', 'born' => '1973']);
    $request = $this->request();

    // The order is important
    expect($request->params())->toBe([
        'first_band' => 'Mantas',
        'born' => '1967',
        'chuck' => 'schuldiner',
    ]);
});


test('Request::redirect temporary', function () {
    $thrown = false;

    try {
        $request = $this->request();
        $request->redirect('/login');
    } catch (ExitException) {
        $thrown = true;
    }

    expect($thrown)->toBe(true);
    expect(http_response_code())->toBe(302);
});


test('Request::redirect permanent', function () {
    $thrown = false;

    try {
        $request = $this->request();
        $request->redirect('/login', 301);
    } catch (ExitException) {
        $thrown = true;
    }

    expect($thrown)->toBe(true);
    expect(http_response_code())->toBe(301);
});


test('Request::json', function () {
    // Simulates the php://input stream with a temp file
    ob_start();
    $request = $this->request();
    $f = tmpfile();
    $streamName = stream_get_meta_data($f)['uri'];
    fwrite($f, '[{"title": "Leprosy", "released": 1988}, {"title": "Human", "released": 1991}]');
    rewind($f);

    expect($request->json(stream: $streamName))->toBe([
        ["title" => "Leprosy", "released" => 1988],
        ["title" => "Human", "released" => 1991]
    ]);
    fclose($f);
    ob_end_clean();
});


test('Request::json empty', function () {
    // Simulates the php://input stream with a temp file
    ob_start();
    $request = $this->request();
    $f = tmpfile();
    $streamName = stream_get_meta_data($f)['uri'];
    fwrite($f, '');
    rewind($f);

    expect($request->json(stream: $streamName))->toBe(null);
    fclose($f);
    ob_end_clean();
});


test('Request::renderer', function () {
    $request = $this->request();
    $renderer = $request->renderer('json');

    expect($renderer)->toBeInstanceOf(JsonRenderer::class);
});


test('Request::renderer with args', function () {
    $config = $this->config();
    $config->addRenderer('template', TemplateRenderer::class, $this->templates());
    $request = $this->request(config: $config);
    $renderer = $request->renderer('template', 'renderer');

    expect($renderer)->toBeInstanceOf(TemplateRenderer::class);
});


test('Has file', function () {
    $this->setupFile();
    $request = $this->request();

    expect($request->hasFile('myfile'))->toBe(true);
});


test("Doesn't have file", function () {
    $this->setupFile();
    $request = $this->request();

    expect($request->hasFile('nofile'))->toBe(false);
});


test('Has multiple files', function () {
    $this->setupFile(); // Single file
    $request = $this->request();

    expect($request->hasFile('myfile'))->toBe(true);
    expect($request->hasFile('myfile') && $request->hasMultipleFiles('myfile'))->toBe(false);

    $this->setupFiles(); // Uploaded as HTML array
    $request = $this->request();

    expect($request->hasFile('myfile'))->toBe(true);
    expect($request->hasFile('myfile') && $request->hasMultipleFiles('myfile'))->toBe(true);
});


test('Get file instances', function () {
    $this->setupFile();
    $request = $this->request();
    $file = $request->file('myfile');

    expect($file)->toBeInstanceOf(File::class);
    expect($file->isValid())->toBe(true);

    $file = $request->file('failingfile');

    expect($file)->toBeInstanceOf(File::class);
    expect($file->isValid())->toBe(false);
});


test('Get files instances', function () {
    $this->setupFiles(); // files array
    $request = $this->request();
    $files = $request->files('myfile');

    expect(count($files))->toBe(2);
    expect($files[0])->toBeInstanceOf(File::class);
    expect($files[0]->isValid())->toBe(true);
    expect($files[1])->toBeInstanceOf(File::class);
    expect($files[1]->isValid())->toBe(false);
});


test('Get files instances with only one present', function () {
    $this->setupFile(); // single file
    $request = $this->request();
    $files = $request->files('myfile');

    expect(count($files))->toBe(1);
    expect($files[0])->toBeInstanceOf(File::class);
    expect($files[0]->isValid())->toBe(true);
});


test('File instance not available', function () {
    $request = $this->request();
    $files = $request->file('does-not-exist');
})->throws(RuntimeException::class);
