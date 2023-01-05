<?php

declare(strict_types=1);

use Conia\Chuck\Tests\Setup\TestCase;
use Conia\Chuck\App;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Response;

// phpcs:disable
uses(TestCase::class);


function ___functionMiddleware(Request $request, callable $next): Response
{
    error_log('function');
    $response = $next($request);

    return $response->body('first' . (string)$response->getBody());
}


class ___ObjectMiddleware
{
    public function __construct(protected string $text)
    {
    }

    public function __invoke(Request $request, callable $next): Response
    {
        error_log('object');
        // handle next
        $response = $next($request);

        // add another text to the body
        $response->body((string)$response->getBody() . $this->text);

        return $response;
    }
}


class ___EarlyResponseMiddleware
{
    public function __construct(protected string $text, protected Registry $registry)
    {
    }

    public function __invoke(Request $request, callable $_): Response
    {
        $response = (new ResponseFactory($this->registry))->html($this->text);

        return $response;
    }
}
// phpcs:enable

test('Middleware flow', function () {
    $app = App::create($this->config());
    $route = new Route('/', 'Conia\Chuck\Tests\Fixtures\TestController::middlewareView');
    $route->middleware(new ___ObjectMiddleware(' last'));
    $app->addRoute($route);
    $app->middleware('___functionMiddleware');

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('first view last');
});


test('Middleware flow with attribute', function () {
    $app = App::create($this->config());
    $route = new Route('/', 'Conia\Chuck\Tests\Fixtures\TestController::attributedMiddlewareView');
    $route->middleware(new ___ObjectMiddleware(' last'));
    $app->addRoute($route);
    $app->middleware('___functionMiddleware');

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('first attribute-string last');
});


test('Early response', function () {
    $app = App::create($this->config());
    $app->route('/', 'Conia\Chuck\Tests\Fixtures\TestController::middlewareView');
    $app->middleware(new ___EarlyResponseMiddleware('immediate response', $this->registry()));
    $app->middleware(new ___ObjectMiddleware(' second'));

    ob_start();
    $app->run();
    $output = ob_get_contents();
    ob_end_clean();

    expect($output)->toBe('immediate response');
});
