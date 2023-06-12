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

test('HTTP Errors', function () {
    $exception = HttpBadRequest::withPayload('400 payload');
    expect($exception->getTitle())->toBe('400 Bad Request');
    expect($exception->getCode())->toBe(400);
    expect($exception->getPayload())->toBe('400 payload');

    $exception = HttpUnauthorized::withPayload('401 payload');
    expect($exception->getTitle())->toBe('401 Unauthorized');
    expect($exception->getCode())->toBe(401);
    expect($exception->getPayload())->toBe('401 payload');

    $exception = HttpForbidden::withPayload('403 payload');
    expect($exception->getTitle())->toBe('403 Forbidden');
    expect($exception->getCode())->toBe(403);
    expect($exception->getPayload())->toBe('403 payload');

    $exception = HttpNotFound::withPayload('404 payload');
    expect($exception->getTitle())->toBe('404 Not Found');
    expect($exception->getCode())->toBe(404);
    expect($exception->getPayload())->toBe('404 payload');

    $exception = HttpMethodNotAllowed::withPayload('405 payload');
    expect($exception->getTitle())->toBe('405 Method Not Allowed');
    expect($exception->getCode())->toBe(405);
    expect($exception->getPayload())->toBe('405 payload');

    $exception = HttpServerError::withPayload('500 payload');
    expect($exception->getTitle())->toBe('500 Internal Server Error');
    expect($exception->getCode())->toBe(500);
    expect($exception->getPayload())->toBe('500 payload');
});

test('Error handler I', function () {
    $err = new Handler($this->registry());

    expect($err->handleError(0, 'Chuck Test'))->toBe(false);
});

test('Error handler II', function () {
    $err = new Handler($this->registry());

    expect($err->handleError(E_WARNING, 'Chuck Test'))->toBe(false);
})->throws(ErrorException::class, 'Chuck Test');

test('HTTP error responses', function () {
    $err = new Handler($this->registry());

    $response = $err->getResponse($err->getError(new HttpBadRequest()), $this->request());
    expect((string)$response->psr()->getBody())->toContain('<h1>400 Bad Request</h1>');

    $response = $err->getResponse($err->getError(new HttpUnauthorized()), $this->request());
    expect((string)$response->psr()->getBody())->toContain('<h1>401 Unauthorized</h1>');

    $response = $err->getResponse($err->getError(new HttpForbidden()), $this->request());
    expect((string)$response->psr()->getBody())->toContain('<h1>403 Forbidden</h1>');

    $response = $err->getResponse($err->getError(new HttpNotFound()), $this->request());
    expect((string)$response->psr()->getBody())->toContain('<h1>404 Not Found</h1>');

    $response = $err->getResponse($err->getError(new HttpMethodNotAllowed()), $this->request());
    expect((string)$response->psr()->getBody())->toContain('<h1>405 Method Not Allowed</h1>');

    $response = $err->getResponse($err->getError(new HttpServerError()), $this->request());
    expect((string)$response->psr()->getBody())->toContain('<h1>500 Internal Server Error</h1>');
});

test('Response with text/plain', function () {
    $_SERVER['HTTP_ACCEPT'] = 'text/plain';
    $err = new Handler($this->registry());

    $response = $err->getResponse($err->getError(new HttpBadRequest()), $this->request());
    expect((string)$response->psr()->getBody())->toBe('Error: 400 Bad Request');
});

test('Response with application/json', function () {
    $_SERVER['HTTP_ACCEPT'] = 'application/json';
    $err = new Handler($this->registry());

    $response = $err->getResponse($err->getError(new HttpBadRequest()), $this->request());
    $error = json_decode((string)$response->psr()->getBody());

    expect($error->error)->toBe('400 Bad Request');
    expect($error->description)->toBe('Bad Request');
    expect($error->traceback)->toContain('#0');
    expect($error->code)->toBe(400);
    expect($error->payload)->toBe(null);
});

test('Response with PHP Exceptions', function () {
    $err = new Handler($this->registry());
    $response = $err->getResponse($err->getError(new DivisionByZeroError('Division by zero')), $this->request());

    expect((string)$response->psr()->getBody())->toContain('<h1>500 Internal Server Error</h1>');
});

test('Handled by middleware', function () {
    $app = App::create();
    $app->route('/', fn () => '');
    ob_start();
    $response = $app->run();
    ob_end_clean();

    expect((string)$response->getBody())->toContain('<title>500 Internal Server Error</title>');
    expect((string)$response->getBody())->toContain('<h1>500 Internal Server Error</h1>');
});

test('Emit PHP Exceptions', function () {
    $err = new Handler($this->registry());

    ob_start();
    $err->emitException(new DivisionByZeroError('Division by zero'));
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toContain('<title>500 Internal Server Error</title>');
    expect($output)->toContain('<h1>500 Internal Server Error</h1>');
});
