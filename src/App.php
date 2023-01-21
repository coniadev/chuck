<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Di\Entry;
use Conia\Chuck\Error\ErrorRenderer;
use Conia\Chuck\Error\Handler;
use Conia\Chuck\Http\Emitter;
use Conia\Chuck\Middleware;
use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Registry;
use Conia\Chuck\Renderer\HtmlErrorRenderer;
use Conia\Chuck\Renderer\HtmlRenderer;
use Conia\Chuck\Renderer\JsonErrorRenderer;
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Renderer\TextErrorRenderer;
use Conia\Chuck\Renderer\TextRenderer;
use Conia\Chuck\Routing\AddsRoutes;
use Conia\Chuck\Routing\RouteAdder;
use Psr\Container\ContainerInterface as PsrContainer;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequest;
use Psr\Http\Server\MiddlewareInterface as PsrMiddleware;
use Psr\Log\LoggerInterface as PsrLogger;

class App implements RouteAdder
{
    use AddsRoutes;

    public function __construct(
        protected Config $config,
        protected Router $router,
        protected Registry $registry,
        protected Middleware|PsrMiddleware|null $errorHandler = null,
    ) {
        self::initializeRegistry($registry, $config, $router);

        if ($errorHandler) {
            // The error handler should be the first middleware
            $router->middleware($errorHandler);
        }
    }

    public static function create(?Config $config = null, ?PsrContainer $container = null): self
    {
        if (!$config) {
            $config = new Config('chuck', debug: false);
        }

        $registry = new Registry($container);
        $router = new Router();
        $errorHandler = new Handler($config, $registry);

        return new self($config, $router, $registry, $errorHandler);
    }

    public function router(): Router
    {
        return $this->router;
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function registry(): Registry
    {
        return $this->registry;
    }

    /** @psalm-param Closure(Router $router):void $creator */
    public function routes(Closure $creator, string $cacheFile = '', bool $shouldCache = true): void
    {
        $this->router->routes($creator, $cacheFile, $shouldCache);
    }

    public function addRoute(Route $route): Route
    {
        return $this->router->addRoute($route);
    }

    public function addGroup(Group $group): void
    {
        $this->router->addGroup($group);
    }

    public function group(
        string $patternPrefix,
        Closure $createClosure,
        string $namePrefix = '',
    ): Group {
        $group = new Group($patternPrefix, $createClosure, $namePrefix);
        $this->router->addGroup($group);

        return $group;
    }

    public function staticRoute(
        string $prefix,
        string $path,
        string $name = '',
    ): void {
        $this->router->addStatic($prefix, $path, $name);
    }

    /**
     * @param Middleware|callable(
     *     Request,
     *     callable
     * ):\Conia\Chuck\Response $middleware
     *
     * TODO: Why can't we import the custom psalm type MiddlewareCallable from Middleware
     */
    public function middleware(Middleware|callable ...$middleware): void
    {
        $this->router->middleware(...$middleware);
    }

    /**
     * @psalm-param non-empty-string $name
     * @psalm-param non-empty-string $class
     */
    public function renderer(string $name, string $class): Entry
    {
        return $this->registry->tag(Renderer::class)->add($name, $class);
    }

    /**
     * @psalm-param non-empty-string $contentType
     * @psalm-param non-empty-string $renderer
     */
    public function errorRenderer(string $contentType, string $renderer, mixed ...$args): Entry
    {
        return $this->registry->tag(Handler::class)
            ->add($contentType, ErrorRenderer::class)->args(renderer: $renderer, args: $args);
    }

    /** @param callable(mixed ...$args):PsrLogger $callable */
    public function logger(callable $callback): void
    {
        $this->registry->add(PsrLogger::class, Closure::fromCallable($callback));
    }

    /**
     * @psalm-param non-empty-string $key
     * @psalm-param class-string|object $value
     */
    public function register(string $key, object|string $value): Entry
    {
        return $this->registry->add($key, $value);
    }

    public function run(): PsrResponse
    {
        $factory = $this->registry->get(Factory::class);
        assert($factory instanceof Factory);
        $serverRequest = $factory->request();
        $request = new Request($serverRequest);

        $this->registry->add(PsrServerRequest::class, $serverRequest);
        $this->registry->add($serverRequest::class, $serverRequest);
        $this->registry->add(Request::class, $request);

        $response = $this->router->dispatch($request, $this->registry);

        (new Emitter())->emit($response);

        return $response;
    }

    public static function initializeRegistry(
        Registry $registry,
        Config $config,
        Router $router,
    ): void {
        $registry->add(Config::class, $config);
        $registry->add($config::class, $config);
        $registry->add(Router::class, $router);
        $registry->add($router::class, $router);

        $registry->add(Factory::class, \Conia\Chuck\Psr\Nyholm::class);
        $registry->add(Response::class)->constructor('fromFactory');

        // Add default renderers
        $rendererTag = $registry->tag(Renderer::class);
        $rendererTag->add('text', TextRenderer::class);
        $rendererTag->add('json', JsonRenderer::class);
        $rendererTag->add('html', HtmlRenderer::class);
        $rendererTag->add('textError', TextErrorRenderer::class);
        $rendererTag->add('jsonError', JsonErrorRenderer::class);
        $rendererTag->add('htmlError', HtmlErrorRenderer::class);

        // Register mimetypes which are compared to the Accept header on error.
        // If the header matches a registered Renderer
        $handlerTag = $registry->tag(Handler::class);
        $handlerTag->add('text/plain', ErrorRenderer::class)->args(renderer: 'textError', args: []);
        $handlerTag->add('text/html', ErrorRenderer::class)->args(renderer: 'htmlError', args: []);
        $handlerTag->add('application/json', ErrorRenderer::class)->args(renderer: 'jsonError', args: []);
    }
}
