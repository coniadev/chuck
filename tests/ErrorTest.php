<?php

declare(strict_types=1);

use Chuck\Error\Handler;
use Chuck\Error\HttpBadRequest;
use Chuck\Error\HttpForbidden;
use Chuck\Error\HttpNotFound;
use Chuck\Error\HttpServerError;
use Chuck\Error\HttpUnauthorized;
use Chuck\Tests\Setup\TestCase;

uses(TestCase::class);


test('Initialize handler', function () {
    // capture output of error_log calls in a temporary file
    // to prevent it printed to the console.
    $default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);

    $err = new Handler($this->request());
    $result = $err->setup();

    expect(is_callable($result))->toBe(true);

    restore_error_handler();
    restore_exception_handler();
    ini_set('error_log', $default);
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
    $default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);
    $err = new Handler($this->request());
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
    $err->handleException(new HttpNotFound());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>404 Not Found</h1><h2>HTTP Error</h2>');

    ob_start();
    $err->handleException(new HttpServerError());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>500 Internal Server Error</h1><h2>HTTP Error</h2>');

    restore_error_handler();
    restore_exception_handler();
    ini_set('error_log', $default);
});



test('Handle PHP Exceptions', function () {
    $default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);
    $err = new Handler($this->request());
    $err->setup();

    ob_start();
    $err->handleException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toBe('<h1>500 Internal Server Error</h1><h2>Division by zero</h2>');

    restore_error_handler();
    restore_exception_handler();
    ini_set('error_log', $default);
});



test('Debug mode traceback', function () {
    $default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);
    $err = new Handler($this->request(config: $this->config(['debug' => true])));
    $err->setup();

    ob_start();
    $err->handleException(new HttpBadRequest());
    $output = ob_get_contents();
    ob_end_clean();
    expect($output)->toStartWith('<h1>400 Bad Request</h1><h2>HTTP Error</h2>');

    restore_error_handler();
    restore_exception_handler();
    ini_set('error_log', $default);
});
