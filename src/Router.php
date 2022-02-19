<?php

declare(strict_types=1);

namespace Chuck;

use \Closure;
use \ValueError;
use \RuntimeException;

use Chuck\Error\HttpNotFound;
use Chuck\Error\HttpServerError;


class Router implements RouterInterface
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected readonly Route $route;
    protected array $routes = [];
    protected array $staticRoutes = [];
    protected array $names = [];
    protected array $middlewares = [];

    public function getRoutes(): array
    {
        return $this->routes;
    }

    public function getRoute(): Route
    {
        try {
            return $this->route;
        } catch (\Throwable) {
            throw new RuntimeException('Route is not initialized');
        }
    }

    public function addRoute(RouteInterface $route): void
    {
        $name = $route->name();

        if (array_key_exists($name, $this->names)) {
            throw new \ErrorException('Duplicate route name: ' . $name);
        }

        $this->routes[] = $route;
        $this->names[$name] = $route;
    }

    public function addStatic(
        string $name,
        string $prefix,
        string $dir,
    ): void {
        if (is_dir($dir)) {
            $this->staticRoutes[$name] = [
                'prefix' => '/' . trim($prefix, '/') . '/',
                'dir' => $dir,
            ];
        } else {
            throw new \InvalidArgumentException("The static directory does not exist: $dir");
        }
    }

    public function middleware(object|string $middleware): void
    {
        if ($middleware instanceof Closure) {
            $reflectionFunc = new \ReflectionFunction($middleware);
        } elseif (is_object($middleware)) {
            $reflectionFunc = (new \ReflectionObject($middleware))->getMethod('__invoke');
        } elseif (is_callable($middleware)) {
            $reflectionFunc = new \ReflectionFunction($middleware);
        } else {
            throw new \InvalidArgumentException("Middleware is not compatible");
        }

        // Check the return type of the middleware
        try {
            $t = $reflectionFunc->getReturnType();
            $returnType = (string)$t ?:
                throw new \InvalidArgumentException("Middleware return type must be given");
            $types = explode('|', $returnType);

            if (count($types) !== 2) {
                throw new ValueError("No union type ($returnType)");
            }

            /** @var class-string $type */
            foreach ($types as $type) {
                $returnTypeCls = new \ReflectionClass($type);

                if (!($returnTypeCls->implementsInterface(RequestInterface::class) ||
                    $returnTypeCls->implementsInterface(ResponseInterface::class)
                )) {
                    throw new ValueError("Wrong return type $returnType");
                }
            }
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException(
                $e->getMessage() . ": " .
                    "Middleware's return type must implement " . RequestInterface::class .
                    "|" . ResponseInterface::class
            );
        }

        // Check if two parameters are present
        $reflectionParams = $reflectionFunc->getParameters();
        if (count($reflectionParams) !== 2) {
            throw new \InvalidArgumentException("Middleware must accept two parameters");
        }

        // Check $request parameter
        $t = $reflectionParams[0]->getType();
        $requestType = (string)$t ?:
            throw new \InvalidArgumentException("Middleware's first parameter must implement " . RequestInterface::class);

        if (class_exists($requestType) || interface_exists($requestType)) {
            $requestTypeCls = new \ReflectionClass($requestType);
            if (
                !($requestType === RequestInterface::class) &&
                !($requestTypeCls->implementsInterface(RequestInterface::class))
            ) {
                throw new \InvalidArgumentException("Middleware's first parameter must implement " . RequestInterface::class);
            }
        } else {
            throw new \InvalidArgumentException("Middleware's first parameter must implement " . RequestInterface::class);
        }

        // Check $next parameter
        $nextType = (string)$reflectionParams[1]->getType();

        if ($nextType !== 'callable') {
            throw new \InvalidArgumentException("Middleware's second parameter must be of type 'callable'");
        }

        $this->middlewares[] = $middleware;
    }

    public function middlewares(): array
    {
        return $this->middlewares;
    }

    public function routeUrl(string $name, mixed ...$args): string
    {
        $route = $this->names[$name] ?? null;

        if ($route) {
            return $route->url(...$args);
        }

        throw new \RuntimeException('Route not found: ' . $name);
    }

    protected function getCacheBuster(string $dir, string $path): string
    {
        $ds = DIRECTORY_SEPARATOR;
        $file = $dir . $ds . ltrim(str_replace('/', $ds, $path), $ds);

        if (file_exists($file)) {
            return substr(md5((string)filemtime($file)), 0, 6);
        }

        return '';
    }

    public function staticUrl(
        string $name,
        string $path,
        bool $bust = false,
        string $host = null
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
            $path .= $sep . 'v=' . $this->getCacheBuster($route['dir'], $file);
        }

        return ($host ? trim($host, '/') : '') . $route['prefix'] . trim($path, '/');
    }

    public function match(RequestInterface $request): ?Route
    {
        foreach ($this->routes as $route) {
            if ($route->match($request)) {
                return $route;
            }
        }

        return null;
    }

    protected function getViewResult(RouteInterface $route, RequestInterface $request): mixed
    {
        $view = $route->view();

        if (is_callable($view)) {
            return $view($request);
        } elseif (is_string($view)) {
            if (!str_contains($view, '::')) {
                $view .= '::__invoke';
            }

            [$ctrlName, $method] = explode('::', $view);

            if (class_exists($ctrlName)) {
                $ctrl = new $ctrlName($request);

                if (method_exists($ctrl, $method)) {
                    return $ctrl->$method($request);
                } else {
                    throw HttpServerError::withSubTitle("Controller method not found $view");
                }
            } else {
                throw HttpServerError::withSubTitle("Controller not found ${ctrlName}");
            }
        } else {
            throw new ValueError('Wrong view type');
        }
    }

    protected function respond(RequestInterface $request, RouteInterface $route): ResponseInterface
    {
        $result = $this->getViewResult($route, $request);

        if ($result instanceof ResponseInterface) {
            return $result;
        } else {
            $config = $request->getConfig();
            $renderer = $route->getRenderer();

            if ($renderer) {
                $rendererObj = new ($config->renderer($renderer->type))($request, $result, $renderer->args);
                $response = $request->getResponse();
                $response->setBody($rendererObj->render());

                foreach ($rendererObj->headers() as $header) {
                    $response->addHeader($header['name'], $header['value'], $header['replace'] ?? true);
                }

                return $response;
            }

            if (is_string($result)) {
                return $request->getResponse(body: $result);
            }

            throw HttpServerError::withSubTitle("No renderer specified and view result is neither a response object nor a string.");
        }
    }

    /**
     * Recursively calls the callables in the middleware/view handler stack.
     * The last one is assumed to be the view/action.
     */
    protected function workOffStack(
        RequestInterface|ResponseInterface $requestResponse,
        array $handlerStack,
    ): RequestInterface|ResponseInterface {
        // If a ResponseInterface is passed, the request is considered done.
        // So the processing exists ahead of time.
        if ($requestResponse instanceof ResponseInterface) {
            return $requestResponse;
        }

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
     * Finds the matching route and generates the response while
     * working of the middleware stack.
     *
     * @psalm-suppress InvalidReturnType
     *
     * See notes at the return statement.
     */
    public function dispatch(RequestInterface $request): ResponseInterface
    {
        $route = $this->match($request);

        if ($route) {
            /**
             * @psalm-suppress InaccessibleProperty
             *
             * TODO: At the time of writing Psalm did not support
             * readonly properties which are not initialized in the
             * constructor. Recheck on occasion.
             */
            $this->route = $route;
            $handlerStack = array_merge(
                $this->middlewares,
                $route->middlewares(),
            );
            $handlerStack[] = function (RequestInterface $req) use ($route): ResponseInterface {
                return $this->respond($req, $route);
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
        } else {
            throw new HttpNotFound();
        }
    }
}
