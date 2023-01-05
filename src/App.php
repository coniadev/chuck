<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Throwable;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Entry;
use Conia\Chuck\Registry;
use Conia\Chuck\Routing\{Route, Group, Router, AddsRoutes};
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

/** @psalm-consistent-constructor */
class App
{
    use AddsRoutes;

    public function __construct(
        private Config $config,
        private Router $router,
        private Registry $registry,
    ) {
        $registry->add(Config::class, $config);
        $registry->add($config::class, $config);
        $registry->add(Router::class, $router);
        $registry->add($router::class, $router);
        $registry->add(App::class, $this);

        // Self register Registry for autowiring
        $registry->add($registry::class, $registry);
    }

    public static function create(Config $config): static
    {
        $registry = new Registry();
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

    public function addRoute(Route $route): void
    {
        $this->router->addRoute($route);
    }

    public function addGroup(Group $group): void
    {
        $this->router->addGroup($group);
    }

    public function group(
        string $patternPrefix,
        Closure $createClosure,
        ?string $namePrefix = null,
    ): Group {
        $group = new Group($patternPrefix, $createClosure, $namePrefix);
        $this->router->addGroup($group);

        return $group;
    }

    public function staticRoute(
        string $prefix,
        string $path,
        ?string $name = null,
    ): void {
        $this->router->addStatic($prefix, $path, $name);
    }

    /**
     * @param MiddlewareInterface|callable(
     *     Request,
     *     callable
     * ):\Conia\Chuck\Response $middlewares
     *
     * TODO: Why can't we import the custom psalm type MiddlewareCallable from MiddlewareInterface
     */
    public function middleware(MiddlewareInterface|callable ...$middlewares): void
    {
        $this->router->middleware(...$middlewares);
    }

    /**
     * @param non-empty-string $key
     * @param object|class-string $value
     * */
    public function register(string $key, object|string $value): Entry
    {
        return $this->registry->add($key, $value);
    }

    protected function registerServerRequest(): void
    {
        $this->registry->add(ServerRequestInterface::class, function (): ServerRequestInterface {
            try {
                $psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();
                $creator = new \Nyholm\Psr7Server\ServerRequestCreator(
                    $psr17Factory, // ServerRequestFactory
                    $psr17Factory, // UriFactory
                    $psr17Factory, // UploadedFileFactory
                    $psr17Factory  // StreamFactory
                );
                return $creator->fromGlobals();
                // @codeCoverageIgnoreStart
            } catch (Throwable $e) {
                throw new RuntimeException('Install nyholm/psr7-server');
                // @codeCoverageIgnoreEnd
            }
        });
    }

    public function run(): Response
    {
        if (!$this->registry->has(ServerRequestInterface::class)) {
            $this->registerServerRequest();
        }

        if (!$this->registry->has(ResponseFactoryInterface::class)) {
            $this->registry->add(ResponseFactoryInterface::class, \Nyholm\Psr7\Factory\Psr17Factory::class);
        }

        if (!$this->registry->has(StreamFactoryInterface::class)) {
            $this->registry->add(StreamFactoryInterface::class, \Nyholm\Psr7\Factory\Psr17Factory::class);
        }

        $serverRequest = $this->registry->resolve(ServerRequestInterface::class);
        $request = new Request($serverRequest);

        $this->registry->add(Request::class, $request);
        $this->registry->add(ResponseFactory::class, new ResponseFactory($this->registry));

        $response = $this->router->dispatch($request, $this->config, $this->registry);

        (new Emitter())->emit($response->psr7());

        return $response;
    }
}
