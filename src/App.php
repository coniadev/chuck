<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\Registry\Entry;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Renderer\TextRenderer;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Routing\AddsRoutes;
use Conia\Chuck\Routing\Group;
use Conia\Chuck\Routing\Route;
use Conia\Chuck\Routing\Router;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

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

    public static function create(?Config $config = null, ?ContainerInterface $container = null): static
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
     * @psalm-param non-empty-string $name
     * @psalm-param non-empty-string $class
     */
    public function renderer(string $name, string $class): Entry
    {
        return $this->registry->tag(Renderer::class)->add($name, $class)->asIs();
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
        $serverRequest = $this->registry->get(ServerRequestInterface::class);
        assert($serverRequest instanceof ServerRequestInterface);
        $request = new Request($serverRequest);
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

        $registry->add(ResponseFactoryInterface::class, \Nyholm\Psr7\Factory\Psr17Factory::class);
        $registry->add(StreamFactoryInterface::class, \Nyholm\Psr7\Factory\Psr17Factory::class);
        $registry->add(ResponseFactory::class, new ResponseFactory($this->registry));
        $registry->add(ServerRequestInterface::class, function (): ServerRequestInterface {
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

        $registry->tag(Renderer::class)->add('text', TextRenderer::class)->asIs();
        $registry->tag(Renderer::class)->add('json', JsonRenderer::class)->asIs();
    }
}
