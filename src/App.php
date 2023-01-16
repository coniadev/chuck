<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Middleware;
use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Registry\Entry;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Renderer\TextRenderer;
use Conia\Chuck\Routing\AddsRoutes;
use Conia\Chuck\Routing\Group;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\Routing\RouteAdder;
use Conia\Chuck\Routing\Router;
use Psr\Container\ContainerInterface as PsrContainer;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequest;
use Psr\Log\LoggerInterface as PsrLogger;

/** @psalm-consistent-constructor */
class App implements RouteAdder
{
    use AddsRoutes;

    public function __construct(
        protected Config $config,
        protected Router $router,
        protected Registry $registry,
    ) {
        $this->initializeRegistry();
    }

    public static function create(?Config $config = null, ?PsrContainer $container = null): static
    {
        if (!$config) {
            $config = new Config('chuck', debug: false);
        }

        $registry = new Registry($container);
        $router = new Router();

        $errorHandler = new ErrorHandler($config, $registry);
        $errorHandler->setup();

        return new static($config, $router, $registry);
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

    public function run(): Response
    {
        $factory = $this->registry->get(Factory::class);
        assert($factory instanceof Factory);
        $serverRequest = $factory->request();
        $request = new Request($serverRequest);

        $this->registry->add(PsrServerRequest::class, $serverRequest);
        $this->registry->add($serverRequest::class, $serverRequest);
        $this->registry->add(Request::class, $request);

        $response = $this->router->dispatch($request, $this->registry);

        (new Emitter())->emit($response->psr7());

        return $response;
    }

    protected function initializeRegistry(): void
    {
        $registry = $this->registry;

        $registry->add(Config::class, $this->config);
        $registry->add($this->config::class, $this->config);
        $registry->add(Router::class, $this->router);
        $registry->add($this->router::class, $this->router);
        $registry->add(App::class, $this);

        $registry->add(Factory::class, \Conia\Chuck\Psr\Nyholm::class);
        $registry->add(Response::class, function (Registry $registry): Response {
            $factory = $registry->get(Factory::class);
            assert($factory instanceof Factory);

            return new Response($factory->response(), $factory);
        });

        $registry->tag(Renderer::class)->add('text', TextRenderer::class);
        $registry->tag(Renderer::class)->add('json', JsonRenderer::class);
    }
}
