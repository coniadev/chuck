<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\App;
use Chuck\Request;
use Chuck\Response\Response;
use Chuck\Routing\Route;

uses(TestCase::class);


function ___functionMiddleware(Request $request, callable $next): Request|Response
{
    $response = $next($request);

    return $response->body('first' . $response->getBody());
}


class ___ObjectMiddleware
{
    public function __construct(protected string $text)
    {
    }

    public function __invoke(Request $request, callable $next): Request|Response
    {
        // add $text from constructor
        // $response = $request->response($this->text);
        // error_log($response->getBody());

        // handle next
        $response = $next($request);

        // add another text to the body
        $response->body($response->getBody() . $this->text);

        return $response;
    }
}


class ___EarlyResponseMiddleware
{
    public function __construct(protected string $text)
    {
    }

    public function __invoke(Request $request, callable $next): Request|Response
    {
        $response = $request->response($this->text);

        return $response;
    }
}

test('Middleware flow', function () {
    $app = App::create($this->config());
    $app->add(Route::get('index', '/', 'Chuck\Tests\Fixtures\TestController::middlewareView'));
    $app->middleware('___functionMiddleware');
    $app->middleware(new ___ObjectMiddleware(' last'));

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('first view last');
});


test('Early response', function () {
    $app = App::create($this->config());
    $app->add(Route::get('index', '/', 'Chuck\Tests\Fixtures\TestController::middlewareView'));
    $app->middleware(new ___EarlyResponseMiddleware('immediate response'));
    $app->middleware(new ___ObjectMiddleware(' second'));

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('immediate response');
});


test('Middleware validation', function () {
    // debug => true activates middleware validation
    $app = App::create($this->config(debug: true));
    $app->add(Route::get('index', '/', 'Chuck\Tests\Fixtures\TestController::middlewareView'));
    $app->middleware(function () {
    });
    $app->run();
})->throws(TypeError::class, 'return type must implement');
