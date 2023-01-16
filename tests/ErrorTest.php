<?php

declare(strict_types=1);

use Conia\Chuck\App;
use Conia\Chuck\Config;
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
    $err = new Handler($this->config(), $this->registry());

    expect($err->handleError(0, 'Chuck Test'))->toBe(false);
});


test('Error handler II', function () {
    $err = new Handler($this->config(), $this->registry());

    expect($err->handleError(E_WARNING, 'Chuck Test'))->toBe(false);
})->throws(ErrorException::class, 'Chuck Test');


test('Handle HTTP Exceptions', function () {
    $err = new Handler($this->config(debug: true), $this->registry());

    $response = $err->handleException(new HttpBadRequest());
    expect((string)$response->getBody())->toBe('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');

    $response = $err->handleException(new HttpUnauthorized());
    expect((string)$response->getBody())->toBe('<h1>401 Unauthorized</h1><h2>HTTP Error</h2>');

    $response = $err->handleException(new HttpForbidden());
    expect((string)$response->getBody())->toBe('<h1>403 Forbidden</h1><h2>HTTP Error</h2>');

    $response = $err->handleException(HttpNotFound::withSubtitle("I've searched everywhere"));
    expect((string)$response->getBody())->toBe('<h1>404 Not Found</h1><h2>I&#039;ve searched everywhere</h2>');

    $response = $err->handleException(new HttpMethodNotAllowed());
    expect((string)$response->getBody())->toBe('<h1>405 Method Not Allowed</h1><h2>HTTP Error</h2>');

    $response = $err->handleException(new HttpServerError());
    expect((string)$response->getBody())->toStartWith('<h1>500 Internal Server Error</h1><h2>HTTP Error</h2>');
    expect((string)$response->getBody())->toContain('<br>#1');
});


test('Handle PHP Exceptions', function () {
    $err = new Handler($this->config(), $this->registry());
    $response = $err->handleException(new DivisionByZeroError('Division by zero'));

    expect((string)$response->getBody())->toBe('<h1>500 Internal Server Error</h1>');
});


test('Debug mode traceback', function () {
    $err = new Handler($this->config(debug: true), $this->registry());

    $response = $err->handleException(new HttpBadRequest());
    expect((string)$response->getBody())->toStartWith('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');
});


test('Handled by middleware', function () {
    $app = App::create();
    $app->route('/', fn () => '');
    ob_start();
    $response = $app->run();
    ob_end_clean();

    expect((string)$response->getBody())->toBe('<h1>500 Internal Server Error</h1>');
});


test('Handled by middleware (debug: true)', function () {
    $app = App::create(new Config('chuck', debug: true));
    $app->route('/', fn () => '');
    ob_start();
    $response = $app->run();
    ob_end_clean();

    expect((string)$response->getBody())->toStartWith('<h1>500 Internal Server Error</h1><h2>Unable to');
});


test('Emit PHP Exceptions', function () {
    $err = new Handler($this->config(), $this->registry());

    ob_start();
    $err->emitException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>500 Internal Server Error</h1>');
});


test('Emit PHP Exceptions (debug: true)', function () {
    $err = new Handler($this->config(debug: true), $this->registry());

    ob_start();
    $err->emitException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toStartWith('<h1>500 Internal Server Error</h1><h2>Division by zero</h2>');
});
