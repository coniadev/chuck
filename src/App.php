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
        protected Config $config,
        protected Router $router,
        protected Registry $registry,
    ) {
        $this->initializeRegistry();
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
     * ):\Conia\Chuck\Response $middleware
     *
     * TODO: Why can't we import the custom psalm type MiddlewareCallable from MiddlewareInterface
     */
    public function middleware(MiddlewareInterface|callable ...$middleware): void
    {
        $this->router->middleware(...$middleware);
    }

    /**
     * @param non-empty-string $key
     * @param object|class-string $value
     * */
    public function register(string $key, object|string $value): Entry
    {
        return $this->registry->add($key, $value);
    }

    protected function initializeRegistry(): void
    {
        $registry = $this->registry;

        $registry->addAnyway(Config::class, $this->config);
        $registry->addAnyway($this->config::class, $this->config);
        $registry->addAnyway(Router::class, $this->router);
        $registry->addAnyway($this->router::class, $this->router);
        $registry->addAnyway(App::class, $this);

        $registry->addAnyway(ResponseFactoryInterface::class, \Nyholm\Psr7\Factory\Psr17Factory::class);
        $registry->addAnyway(StreamFactoryInterface::class, \Nyholm\Psr7\Factory\Psr17Factory::class);
        $registry->addAnyway(ResponseFactory::class, new ResponseFactory($this->registry));
        $registry->addAnyway(ServerRequestInterface::class, function (): ServerRequestInterface {
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
            } catch (Throwable) {
                throw new RuntimeException('Install nyholm/psr7-server');
                // @codeCoverageIgnoreEnd
            }
        });
    }

    public function run(): Response
    {
        $serverRequest = $this->registry->get(ServerRequestInterface::class);
        assert($serverRequest instanceof ServerRequestInterface);
        $request = new Request($serverRequest);
        $this->registry->addAnyway(Request::class, $request);

        $response = $this->router->dispatch($request, $this->config, $this->registry);

        (new Emitter())->emit($response->psr7());

        return $response;
    }
}
