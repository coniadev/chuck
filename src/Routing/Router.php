<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Closure;
use JsonException;
use Stringable;
use Throwable;
use Conia\Chuck\Attribute\Render;
use Conia\Chuck\Config;
use Conia\Chuck\Exception\{HttpNotFound, HttpMethodNotAllowed, RuntimeException};
use Conia\Chuck\MiddlewareInterface;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\View\View;
use Conia\Chuck\View\CallableView;
use Conia\Chuck\View\ControllerView;

class Router
{
    use AddsRoutes;
    use AddsMiddleware;

    protected ?Route $route = null;
    protected ?Registry $registry = null;
    protected ?Config $config = null;
    /** @var array<string, list<Route>> */
    protected array $routes = [];
    /** @var array<string, StaticRoute> */
    protected array $staticRoutes = [];
    /** @var array<string, Route> */
    protected array $names = [];

    protected const ALL = 'ALL';

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
            throw new RuntimeException("The static directory does not exist: $dir");
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

            $buster =  $this->getCacheBuster($route->dir, $file);

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

    protected function respond(
        Request $request,
        View $view,
    ): Response {
        /**
         * @psalm-suppress MixedAssignment
         *
         * Later in the function we check the type of $result.
         * */
        $result = $view->execute();

        assert(!is_null($this->config));
        assert(!is_null($this->registry));
        assert(!is_null($this->route));

        if ($result instanceof Response) {
            return $result;
        } else {
            $rendererConfig = $this->route->getRenderer();

            if ($rendererConfig) {
                $renderer = $this->config->renderer(
                    $request,
                    $this->registry,
                    $rendererConfig->type,
                    ...$rendererConfig->args
                );

                return $renderer->response($result);
            }

            $renderAttributes = $view->attributes(Render::class);

            if (count($renderAttributes) > 0) {
                assert($renderAttributes[0] instanceof Render);
                return $renderAttributes[0]->response($request, $this->config, $this->registry, $result);
            }

            $responseFactory = new ResponseFactory($this->registry);

            if (is_string($result)) {
                return $responseFactory->html($result);
            } elseif ($result instanceof Stringable) {
                return $responseFactory->html($result->__toString());
            } else {
                try {
                    return $responseFactory->json($result);
                } catch (JsonException) {
                    throw new RuntimeException('Cannot determine a response handler for the return type of the view');
                }
            }
        }
    }

    /**
     * Recursively calls the callables in the middleware/view handler stack
     * and then the view callable.
     *
     * @psalm-param list<MiddlewareInterface> $handlerStack
     * @psalm-param Closure(Request):Response $viewClosure
     */
    protected function workOffStack(
        Request $request,
        array $handlerStack,
        Closure $viewClosure,
    ): Response {
        return match (count($handlerStack)) {
            0 => $viewClosure($request),
            1 => $handlerStack[0]($request, $viewClosure),
            default => $handlerStack[0](
                $request,
                function (
                    Request $req
                ) use (
                    $handlerStack,
                    $viewClosure
                ): Response {
                    return $this->workOffStack(
                        $req,
                        array_slice($handlerStack, 1),
                        $viewClosure
                    );
                }
            )
        };
    }

    /**
     * Looks up the matching route and generates the response while
     * working off the middleware stack.
     */
    public function dispatch(Request $request, Config $config, Registry $registry): Response
    {
        $this->route = $this->match($request);
        $this->config = $config;
        $this->registry = $registry;

        $routeView = $this->route->view();

        if (is_callable($routeView)) {
            $view = new CallableView($this->route, $registry, $routeView);
        } else {
            /**
             * @psalm-suppress PossiblyInvalidArgument
             *
             * According to Psalm, $view could be a Closure. But since we
             * checked for is_callable before, this can never happen.
             */
            $view = new ControllerView($this->route, $registry, $routeView);
        }

        /** @var list<MiddlewareInterface> */
        $middlewareAttributes = $view->attributes(MiddlewareInterface::class);

        $handlerStack = array_merge(
            $this->middlewares,
            $this->route->middlewares(),
            $middlewareAttributes,
        );

        $viewClosure = function (Request $req) use ($view): Response {
            return $this->respond($req, $view);
        };

        return $this->workOffStack($request, $handlerStack, $viewClosure);
    }
}
