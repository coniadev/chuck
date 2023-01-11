<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Conia\Chuck\Dispatcher;
use Conia\Chuck\Exception\HttpMethodNotAllowed;
use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\MiddlewareWrapper;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Registry\Resolver;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\View;
use Conia\Chuck\ViewHandler;
use Psr\Http\Server\MiddlewareInterface as PsrMiddlewareInterface;
use Throwable;

class Router
{
    use AddsRoutes;
    use AddsMiddleware;

    protected const ALL = 'ALL';

    protected ?Route $route = null;

    /** @psalm-var array<string, list<Route>> */
    protected array $routes = [];

    /** @var array<string, StaticRoute> */
    protected array $staticRoutes = [];

    /** @var array<string, Route> */
    protected array $names = [];

    public function getRoute(): Route
    {
        if (is_null($this->route)) {
            throw new RuntimeException('Route is not initialized');
        }

        return $this->route;
    }

    public function addRoute(Route $route): void
    {
        $name = $route->name();
        $noMethodGiven = true;

        if (array_key_exists($name, $this->names)) {
            throw new RuntimeException(
                'Duplicate route: ' . $name . '. If you want to use the same ' .
                    'url pattern with different methods, you have to create routes with names.'
            );
        }

        foreach ($route->methods() as $method) {
            $noMethodGiven = false;
            $this->routes[$method][] = $route;
        }

        if ($noMethodGiven) {
            $this->routes[self::ALL][] = $route;
        }

        $this->names[$name] = $route;
    }

    public function addGroup(Group $group): void
    {
        $group->create($this);
    }

    public function addStatic(
        string $prefix,
        string $dir,
        ?string $name = null,
    ): void {
        if (empty($name)) {
            $name = $prefix;
        }

        if (array_key_exists($name, $this->staticRoutes)) {
            throw new RuntimeException(
                'Duplicate static route: ' . $name . '. If you want to use the same ' .
                    'url prefix you have to create static routes with names.'
            );
        }

        if (is_dir($dir)) {
            $this->staticRoutes[$name] = new StaticRoute(
                prefix: '/' . trim($prefix, '/') . '/',
                dir: $dir,
            );
        } else {
            throw new RuntimeException("The static directory does not exist: {$dir}");
        }
    }

    public function staticUrl(
        string $name,
        string $path,
        bool $bust = false,
        ?string $host = null
    ): string {
        $route = $this->staticRoutes[$name];

        if ($bust) {
            // Check if there is already a query parameter present
            if (strpos($path, '?')) {
                $file = strtok($path, '?');
                $sep = '&';
            } else {
                $file = $path;
                $sep = '?';
            }

            $buster = $this->getCacheBuster($route->dir, $file);

            if (!empty($buster)) {
                $path .= $sep . 'v=' . $buster;
            }
        }

        return ($host ? trim($host, '/') : '') . $route->prefix . trim($path, '/');
    }

    public function routeUrl(string $__routeName__, mixed ...$args): string
    {
        $route = $this->names[$__routeName__] ?? null;

        if ($route) {
            return $route->url(...$args);
        }

        throw new RuntimeException('Route not found: ' . $__routeName__);
    }

    public function match(Request $request): Route
    {
        $url = $request->uri()->getPath();
        $requestMethod = $request->method();

        foreach ([$requestMethod, self::ALL] as $method) {
            foreach ($this->routes[$method] ?? [] as $route) {
                if ($route->match($url)) {
                    return $route;
                }
            }
        }

        // We know now, that the route does not match.
        // Check if it would match one of the remaining methods
        $wrongMethod = false;
        $remainingMethods = array_keys($this->routes);

        foreach ([$requestMethod, self::ALL] as $method) {
            if (($key = array_search($method, $remainingMethods)) !== false) {
                unset($remainingMethods[$key]);
            }
        }

        foreach ($remainingMethods as $method) {
            foreach ($this->routes[$method] as $route) {
                if ($route->match($url)) {
                    $wrongMethod = true;

                    break;
                }
            }
        }

        if ($wrongMethod) {
            throw new HttpMethodNotAllowed();
        }

        throw new HttpNotFound();
    }

    /**
     * Looks up the matching route and generates the response.
     */
    public function dispatch(Request $request, Registry $registry): Response
    {
        $this->route = $this->match($request);

        $view = new View($this->route->view(), $this->route->args(), $registry);
        $queue = $this->collectMiddleware($view, $registry);
        $queue[] = new ViewHandler($view, $registry, $this->route);

        return (new Dispatcher($queue, $registry))->dispatch($request);
    }

    protected function getCacheBuster(string $dir, string $path): string
    {
        $ds = DIRECTORY_SEPARATOR;
        $file = $dir . $ds . ltrim(str_replace('/', $ds, $path), $ds);

        try {
            return hash('xxh32', (string)filemtime($file));
        } catch (Throwable) {
            return '';
        }
    }

    protected function collectMiddleware(View $view, Registry $registry): array
    {
        $middlewareAttributes = $view->attributes(MiddlewareInterface::class);

        return array_map(
            function (
                MiddlewareInterface|PsrMiddlewareInterface|callable|string $middleware
            ) use ($registry): MiddlewareInterface|PsrMiddlewareInterface {
                if (
                    ($middleware instanceof MiddlewareInterface)
                    || ($middleware instanceof PsrMiddlewareInterface)
                ) {
                    return $middleware;
                }

                if (is_string($middleware) && class_exists($middleware)) {
                    $object = (new Resolver($registry))->autowire($middleware);
                    assert($object instanceof MiddlewareInterface || $object instanceof PsrMiddlewareInterface);

                    return $object;
                }

                if (is_callable($middleware)) {
                    /** @psalm-var callable(Request, callable):Response $middleware */
                    return new MiddlewareWrapper($middleware);
                }

                throw new RuntimeException('Invalid middleware: ' .
                    /** @scrutinizer ignore-type */
                    print_r($middleware, true));
            },
            array_merge(
                $this->middleware,
                isset($this->route) ? $this->route->getMiddleware() : [],
                $middlewareAttributes,
            )
        );
    }
}
