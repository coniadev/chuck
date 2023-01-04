<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Throwable;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\Response\Response;
use Conia\Chuck\Registry\Entry;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Routing\{Route, Group, Router, AddsRoutes};
use Psr\Http\Message\ServerRequestInterface;

/** @psalm-consistent-constructor */
class App
{
    use AddsRoutes;

    /** @var null|Closure():ServerRequestInterface */
    protected ?Closure $serverRequestFactory = null;

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

        $errorHandler = new ErrorHandler($config);
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

    /**
     * @param callable():ServerRequestInterface $factory
     */
    public function setServerRequestFactory(callable $factory): void
    {
        $this->serverRequestFactory = Closure::fromCallable($factory);
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
     * ):\Conia\Chuck\Response\Response $middlewares
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

    public function run(): Response
    {
        if ($this->serverRequestFactory) {
            $serverRequest = ($this->serverRequestFactory)();
        } else {
            try {
                $psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();
                $creator = new \Nyholm\Psr7Server\ServerRequestCreator(
                    $psr17Factory, // ServerRequestFactory
                    $psr17Factory, // UriFactory
                    $psr17Factory, // UploadedFileFactory
                    $psr17Factory  // StreamFactory
                );
                $serverRequest = $creator->fromGlobals();
                // @codeCoverageIgnoreStart
            } catch (Throwable $e) {
                throw new RuntimeException('Install nyholm/psr7 and nyholm/psr7-server');
                // @codeCoverageIgnoreEnd
            }
        }
        $request = new Request($serverRequest);

        $this->registry->add(ServerRequestInterface::class, $serverRequest);
        $this->registry->add(Request::class, $request);

        $response = $this->router->dispatch($request, $this->config, $this->registry);
        $response->emit();

        return $response;
    }
}
