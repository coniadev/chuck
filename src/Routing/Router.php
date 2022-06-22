<?php

declare(strict_types=1);

namespace Chuck\Routing;

use \Closure;
use \ErrorException;
use \JsonException;
use \RuntimeException;
use \Stringable;
use \Throwable;
use Chuck\Error\{HttpNotFound, HttpMethodNotAllowed};
use Chuck\Error\HttpServerError;
use Chuck\Renderer\{
    Config as RendererConfig,
    RendererInterface,
};
use Chuck\RequestInterface;
use Chuck\Response\ResponseInterface;
use Chuck\Util\Reflect;


class Router implements RouterInterface
{
    use AddsRoutes;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected readonly Route $route;
    protected array $routes = [];
    protected array $staticRoutes = [];
    protected array $names = [];
    protected array $middlewares = [];

    protected const ALL = 'ALL';

    public function getRoute(): RouteInterface
    {
        try {
            return $this->route;
        } catch (Throwable) {
            throw new RuntimeException('Route is not initialized');
        }
    }

    public function addRoute(RouteInterface $route): void
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

    public function addGroup(GroupInterface $group): void
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
            $this->staticRoutes[$name] = [
                'prefix' => '/' . trim($prefix, '/') . '/',
                'dir' => $dir,
            ];
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

            $buster =  $this->getCacheBuster($route['dir'], $file);

            if (!empty($buster)) {
                $path .= $sep . 'v=' . $buster;
            }
        }

        return ($host ? trim($host, '/') : '') . $route['prefix'] . trim($path, '/');
    }

    public function addMiddleware(callable ...$middlewares): void
    {
        foreach ($middlewares as $middleware) {
            $this->middlewares[] = $middleware;
        }
    }

    public function middlewares(): array
    {
        return $this->middlewares;
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

    protected function removeQueryString(string $url): string
    {
        return strtok($url, '?');
    }


    public function match(RequestInterface $request): Route
    {
        $url = $this->removeQueryString($_SERVER['REQUEST_URI']);
        $requestMethod = $request->method();

        // Matching routes should be found quite quickly
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
        foreach ($this->routes as $method => $route) {
            if ($method === $requestMethod || $method === self::ALL) {
                continue;
            }

            foreach ($this->routes[$method] as $route) {
                if ($route->match($url)) {
                    $wrongMethod = true;
                }
            }
        }

        if ($wrongMethod) {
            throw new HttpMethodNotAllowed();
        }

        throw new HttpNotFound();
    }

    protected function getViewResult(RouteInterface $route, RequestInterface $request): mixed
    {
        $view = $route->view();

        if (is_callable($view)) {
            return $view(...$this->getViewArgs($view, $request));
        } elseif (is_array($view)) {
            [$ctrlName, $method] = $view;
        } else {
            /** @var string $view */
            if (!str_contains($view, '::')) {
                $view .= '::__invoke';
            }

            [$ctrlName, $method] = explode('::', $view);
        }


        if (class_exists($ctrlName)) {
            $ctrl = new $ctrlName(...Reflect::controllerConstructorParams($ctrlName, $request));

            if (method_exists($ctrl, $method)) {
                return $ctrl->$method(...$this->getViewArgs(
                    Closure::fromCallable([$ctrl, $method]),
                    $request
                ));
            } else {
                $view = $ctrlName . '::' . $method;
                throw HttpServerError::withSubTitle("Controller method not found $view");
            }
        } else {
            throw HttpServerError::withSubTitle("Controller not found ${ctrlName}");
        }
    }

    protected function getRenderer(
        RequestInterface $request,
        RendererConfig $rendererConfig
    ): RendererInterface {
        return $request->config()->renderer(
            $request,
            $rendererConfig->type,
            ...$rendererConfig->args
        );
    }

    protected function respond(RequestInterface $request, RouteInterface $route): ResponseInterface
    {
        $result = $this->getViewResult($route, $request);

        if ($result instanceof ResponseInterface) {
            return $result;
        } else {
            $rendererConfig = $route->getRenderer();

            if ($rendererConfig) {
                $renderer = $this->getRenderer($request, $rendererConfig);

                return $renderer->response($result);
            }

            if (is_string($result)) {
                return $request->response()->html($result);
            } elseif ($result instanceof Stringable) {
                return $request->response()->html($result->__toString());
            } else {
                try {
                    return $request->response()->json($result);
                } catch (JsonException) {
                    throw new RuntimeException('Cannot determine a response handler for the return type of the view');
                }
            }
        }
    }

    /**
     * Determines the arguments passed to the view
     *
     * - If a view parameter implements RequestInterface, the request will be passed.
     * - If names of the view parameters match names of the route arguments
     *   it will try to convert the argument to the parameter type and add it to
     *   the returned args list.
     * - Only string, float, int and RequestInterface are supported.
     */
    protected function getViewArgs(callable $view, RequestInterface $request): array
    {
        $args = [];
        $rf = Reflect::getReflectionFunction($view);
        $params = $rf->getParameters();
        $routeArgs = $this->route->args();
        $errMsg = 'View parameters cannot be resolved. Details: ';

        foreach ($params as $param) {
            $name = $param->getName();

            try {
                $args[$name] = match ((string)$param->getType()) {
                    'int' => is_numeric($routeArgs[$name]) ?
                        (int)$routeArgs[$name] :
                        throw new RuntimeException($errMsg . "Cannot cast '$name' to int"),
                    'float' => is_numeric($routeArgs[$name]) ?
                        (float)$routeArgs[$name] :
                        throw new RuntimeException($errMsg . "Cannot cast '$name' to float"),
                    'string' => $routeArgs[$name],
                    default => Reflect::getRequestParamOrError($request, $param, $name),
                };
            } catch (Throwable $e) {
                // Check if the view parameter has a default value
                if (!array_key_exists($name, $routeArgs) && $param->isOptional()) {
                    $args[$name] = $param->getDefaultValue();

                    continue;
                }

                throw new RuntimeException($errMsg . $e->getMessage());
            }
        }

        assert(count($params) === count($args));

        return $args;
    }

    /**
     * Recursively calls the callables in the middleware/view handler stack.
     * The last one is assumed to be the view/action.
     */
    protected function workOffStack(
        RequestInterface|ResponseInterface $requestResponse,
        array $handlerStack,
    ): RequestInterface|ResponseInterface {
        if (count($handlerStack) > 1) {
            return $handlerStack[0](
                $requestResponse,
                function (RequestInterface $reqResp) use ($handlerStack): RequestInterface|ResponseInterface {
                    return $this->workOffStack($reqResp, array_slice($handlerStack, 1));
                }
            );
        } else {
            return $handlerStack[0]($requestResponse);
        }
    }

    /**
     * Looks up the matching route and generates the response while
     * working of the middleware stack.
     *
     * @psalm-suppress InvalidReturnType
     *
     * See notes at the return statement.
     */
    public function dispatch(RequestInterface $request): ResponseInterface
    {
        /**
         * @psalm-suppress InaccessibleProperty
         *
         * See docs/contributing.md
         */
        $this->route = $this->match($request);

        $handlerStack = array_merge(
            $this->middlewares,
            $this->route->middlewares(),
        );

        if ($request->config()->debug()) {
            foreach ($handlerStack as $middleware) {
                Reflect::validateMiddleware($middleware);
            }
        }

        // Add the view action to the end of the stack
        $handlerStack[] = function (RequestInterface $req): ResponseInterface {
            return $this->respond($req, $this->route);
        };

        /**
         * @psalm-suppress InvalidReturnStatement
         *
         * workOffStack is guaranteed to return a Response in the end.
         * The union type is necessarry to allow recursive calls where
         * the callables deeper down mostly return a Request. But the
         * result at the end should always be a Response.
         */
        return $this->workOffStack($request, $handlerStack);
    }
}
