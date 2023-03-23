<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\Error\Handler;
use Conia\Chuck\Exception\HttpBadRequest;
use Conia\Chuck\Exception\HttpForbidden;
use Conia\Chuck\Exception\HttpMethodNotAllowed;
use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\HttpServerError;
use Conia\Chuck\Exception\HttpUnauthorized;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);

beforeEach(function () {
    // capture output of error_log calls in a temporary file
    // to prevent it printed to the console.
    $this->default = ini_get('error_log');
    $this->tmpfile = tmpfile();
    $this->logfile = stream_get_meta_data($this->tmpfile)['uri'];
    ini_set('error_log', $this->logfile);
});

afterEach(function () {
    // Restore default error_log and handlers
    is_file($this->logfile) && unlink($this->logfile);
    ini_set('error_log', $this->default);
    restore_error_handler();
    restore_exception_handler();
});

test('Error handler I', function () {
    $err = new Handler(false, $this->registry());

    expect($err->handleError(0, 'Chuck Test'))->toBe(false);
});

test('Error handler II', function () {
    $err = new Handler(false, $this->registry());

    expect($err->handleError(E_WARNING, 'Chuck Test'))->toBe(false);
})->throws(ErrorException::class, 'Chuck Test');

test('Handle HTTP Exceptions', function () {
    $err = new Handler(true, $this->registry());

    $response = $err->handleException(new HttpBadRequest(), $this->request());
    expect((string)$response->getBody())->toContain('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('<br>#1');

    $response = $err->handleException(new HttpUnauthorized(), $this->request());
    expect((string)$response->getBody())->toContain('<h1>401 Unauthorized</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('<br>#1');

    $response = $err->handleException(new HttpForbidden(), $this->request());
    expect((string)$response->getBody())->toContain('<h1>403 Forbidden</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('<br>#1');

    $response = $err->handleException(new HttpNotFound(), $this->request());
    expect((string)$response->getBody())->toContain('<h1>404 Not Found</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('<br>#1');

    $response = $err->handleException(new HttpMethodNotAllowed(), $this->request());
    expect((string)$response->getBody())->toContain('<h1>405 Method Not Allowed</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('<br>#1');

    $response = $err->handleException(new HttpServerError(), $this->request());
    expect((string)$response->getBody())->toContain('<h1>500 Internal Server Error</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('<br>#1');
});

test('Handle Exception and render text/plain', function () {
    $_SERVER['HTTP_ACCEPT'] = 'text/plain';
    $err = new Handler(false, $this->registry());

    $response = $err->handleException(new HttpBadRequest(), $this->request());
    expect((string)$response->getBody())->toBe('Error: 400 Bad Request');
});

test('Handle Exception and render text/plain (debug: true)', function () {
    $_SERVER['HTTP_ACCEPT'] = 'text/plain';
    $err = new Handler(true, $this->registry());

    $response = $err->handleException(new HttpBadRequest(), $this->request());
    expect((string)$response->getBody())->toStartWith("Error: 400 Bad Request\n\nDescription: HTTP Error");
    expect((string)$response->getBody())->toContain('#1');
});

test('Handle Exception and render application/json', function () {
    $_SERVER['HTTP_ACCEPT'] = 'application/json';
    $err = new Handler(false, $this->registry());

    $response = $err->handleException(new HttpBadRequest(), $this->request());
    expect((string)$response->getBody())->toBe('{"error":"400 Bad Request"}');
});

test('Handle Exception and render application/json (debug: true)', function () {
    $_SERVER['HTTP_ACCEPT'] = 'application/json';
    $err = new Handler(true, $this->registry());

    $response = $err->handleException(new HttpBadRequest(), $this->request());
    expect((string)$response->getBody())->toStartWith('{"error":"400 Bad Request","description":"HTTP Error"');
    expect((string)$response->getBody())->toContain('#1');
});

test('Handle PHP Exceptions', function () {
    $err = new Handler(false, $this->registry());
    $response = $err->handleException(new DivisionByZeroError('Division by zero'), $this->request());

    expect((string)$response->getBody())->toContain('<h1>500 Internal Server Error</h1>');
    expect((string)$response->getBody())->not()->toContain('<h2>');
});

test('Debug mode traceback', function () {
    $err = new Handler(true, $this->registry());

    $response = $err->handleException(new HttpBadRequest(), null);
    expect((string)$response->getBody())->toContain('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('#1');
});

test('Handled by middleware', function () {
    $app = App::create();
    $app->route('/', fn () => '');
    ob_start();
    $response = $app->run();
    ob_end_clean();

    expect((string)$response->getBody())->toContain('<title>500 Internal Server Error</title>');
    expect((string)$response->getBody())->toContain('<h1>500 Internal Server Error</h1>');
    expect((string)$response->getBody())->not()->toContain('<h2>');
    expect((string)$response->getBody())->not()->toContain('#1');
});

test('Handled by middleware (debug: true)', function () {
    $app = App::create();
    $app->route('/', fn () => '');
    ob_start();
    $response = $app->run();
    ob_end_clean();

    expect((string)$response->getBody())->toContain('<h1>500 Internal Server Error</h1><h2>Unable to');
});

test('Emit PHP Exceptions', function () {
    $err = new Handler(false, $this->registry());

    ob_start();
    $err->emitException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toContain('<title>500 Internal Server Error</title>');
    expect($output)->toContain('<h1>500 Internal Server Error</h1>');
    expect($output)->not()->toContain('<h2>');
    expect($output)->not()->toContain('#1');
});

test('Emit PHP Exceptions (debug: true)', function () {
    $err = new Handler(true, $this->registry());

    ob_start();
    $err->emitException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toContain('<title>500 Internal Server Error</title>');
    expect($output)->toContain('<h1>500 Internal Server Error</h1><h2>Division by zero</h2>');
    expect($output)->toContain('#1');
});
