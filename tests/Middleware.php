<?php

declare(strict_types=1);

use Chuck\Tests\Setup\TestCase;
use Chuck\{App, Route, Request, Response};

uses(TestCase::class);


function functionMiddleware(Request $request, callable $next): Request|Response
{
    $request->response->body($request->response->getBody() . 'first');
    return $next($request);
}

class ObjectMiddleware
{
    public function __construct(protected string $text)
    {
    }

    public function __invoke(Request $request, callable $next): Request|Response
    {
        $response = $request->response;
        // add $text from constructor
        $response->body($response->getBody() . $this->text);
        // handle next
        $result = $next($request);
        // add another text to the body
        $response->body($response->getBody() . ' last');
        return $result;
    }
}

test('Middleware flow', function () {
    $app = App::create($this->options());
    $app->add(Route::get('index', '/', 'Chuck\Tests\Fixtures\TestController::middlewareView'));
    $app->middleware('functionMiddleware');
    $app->middleware(new ObjectMiddleware(' second'));

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();
    print($output . "\n");

    expect($output)->toBe('first second view last');
});
