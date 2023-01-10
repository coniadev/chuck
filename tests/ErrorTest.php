<?php

declare(strict_types=1);

use Conia\Chuck\ErrorHandler;
use Conia\Chuck\Exception\HttpBadRequest;
use Conia\Chuck\Exception\HttpForbidden;
use Conia\Chuck\Exception\HttpMethodNotAllowed;
use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\HttpServerError;
use Conia\Chuck\Exception\HttpUnauthorized;
use Conia\Chuck\Request;
use Conia\Chuck\Routing\Router;
use Conia\Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


beforeEach(function () {
    // capture output of error_log calls in a temporary file
    // to prevent it printed to the console.
    $this->default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);
    $this->tmpfile = tmpfile();
    $this->logfile = stream_get_meta_data($this->tmpfile)['uri'];
});


afterEach(function () {
    // Restore default error_log and handlers
    is_file($this->logfile) && unlink($this->logfile);
    ini_set('error_log', $this->default);
    restore_error_handler();
    restore_exception_handler();
});


test('Initialize handler', function () {
    $err = new ErrorHandler($this->config(), $this->registry());
    $result = $err->setup();

    expect(is_callable($result))->toBe(true);
});


test('Error handler I', function () {
    $err = new ErrorHandler($this->config(), $this->registry());

    expect($err->handleError(0, 'Chuck Test'))->toBe(false);
});


test('Error handler II', function () {
    $err = new ErrorHandler($this->config(), $this->registry());

    expect($err->handleError(E_WARNING, 'Chuck Test'))->toBe(false);
})->throws(ErrorException::class, 'Chuck Test');


test('Handle HTTP Exceptions', function () {
    $err = new ErrorHandler($this->config(debug: true), $this->registry());
    $err->setup();

    ob_start();
    $err->handleException(new HttpBadRequest());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');

    ob_start();
    $err->handleException(new HttpUnauthorized());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>401 Unauthorized</h1><h2>HTTP Error</h2>');

    ob_start();
    $err->handleException(new HttpForbidden());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>403 Forbidden</h1><h2>HTTP Error</h2>');

    ob_start();
    $err->handleException(HttpNotFound::withSubtitle("I've searched everywhere"));
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>404 Not Found</h1><h2>I&#039;ve searched everywhere</h2>');

    ob_start();
    $err->handleException(new HttpMethodNotAllowed());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>405 Method Not Allowed</h1><h2>HTTP Error</h2>');

    ob_start();
    $err->handleException(new HttpServerError());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toStartWith('<h1>500 Internal Server Error</h1><h2>HTTP Error</h2>');
    expect($output)->toContain('<br>#1');
});


test('Handle PHP Exceptions', function () {
    $err = new ErrorHandler($this->config(), $this->registry());
    $err->setup();

    ob_start();
    $err->handleException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>500 Internal Server Error</h1><h2>Division by zero</h2>');
});


test('Debug mode traceback', function () {
    $err = new ErrorHandler($this->config(debug: true), $this->registry());
    $err->setup();

    ob_start();
    $err->handleException(new HttpBadRequest());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toStartWith('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');
});
