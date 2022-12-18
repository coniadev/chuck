<?php

declare(strict_types=1);

use Conia\Chuck\Request;
use Conia\Chuck\Routing\Router;
use Conia\Chuck\Error\Handler;
use Conia\Chuck\Error\HttpBadRequest;
use Conia\Chuck\Error\HttpForbidden;
use Conia\Chuck\Error\HttpNotFound;
use Conia\Chuck\Error\HttpMethodNotAllowed;
use Conia\Chuck\Error\HttpServerError;
use Conia\Chuck\Error\HttpUnauthorized;
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
    $err = new Handler($this->request());
    $result = $err->setup();

    expect(is_callable($result))->toBe(true);
});


test('Error handler I', function () {
    $err = new Handler($this->request());

    expect($err->handleError(0, 'Chuck Test'))->toBe(false);
});


test('Error handler II', function () {
    $err = new Handler($this->request());

    expect($err->handleError(E_WARNING, 'Chuck Test'))->toBe(false);
})->throws(ErrorException::class, 'Chuck Test');


test('Handle HTTP Exceptions', function () {
    $err = new Handler($this->request(config: $this->config(debug: true)));
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
    expect($output)->toBe("<h1>404 Not Found</h1><h2>I&#039;ve searched everywhere</h2>");

    ob_start();
    $err->handleException(new HttpMethodNotAllowed());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe("<h1>405 Method Not Allowed</h1><h2>HTTP Error</h2>");

    ob_start();
    $err->handleException(new HttpServerError());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toStartWith('<h1>500 Internal Server Error</h1><h2>HTTP Error</h2>');
    expect($output)->toContain('<br>#1');
});


test('Handle PHP Exceptions', function () {
    $err = new Handler($this->request());
    $err->setup();

    ob_start();
    $err->handleException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>500 Internal Server Error</h1><h2>Division by zero</h2>');
});


test('Handle PHP Exceptions :: no server request', function () {
    $savedMethod = $_SERVER['REQUEST_METHOD'];
    unset($_SERVER['REQUEST_METHOD']);

    $request = new Request($this->config());
    $err = new Handler($request);
    $err->setup();

    ob_start();
    $err->handleException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();
    expect(trim($output))->toBe('Division by zero');

    $_SERVER['REQUEST_METHOD'] = $savedMethod;
});


test('Debug mode traceback', function () {
    $err = new Handler($this->request(config: $this->config(debug: true)));
    $err->setup();

    ob_start();
    $err->handleException(new HttpBadRequest());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toStartWith('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');
});
