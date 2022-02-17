<?php

declare(strict_types=1);

namespace Chuck;

use \Closure;
use \ValueError;
use Chuck\Exception\HttpNotFound;
use Chuck\Exception\HttpInternalError;


class Router implements RouterInterface
{
    protected array $routes = [];
    protected array $staticRoutes = [];
    public array $params = [];
    protected array $names = [];
    protected array $middlewares = [];

    public function getRoutes(): array
    {
        return $this->routes;
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
            /** @var class-string */
            $returnType = empty($t) ? $t :
                throw new \InvalidArgumentException("Middleware return type must be given");

            $returnTypeCls = new \ReflectionClass($returnType);

            if (!($returnTypeCls->implementsInterface(RequestInterface::class))) {
                throw new \InvalidArgumentException("Middleware's return type must implement " . RequestInterface::class);
            }
        } catch (\ReflectionException) {
            throw new \InvalidArgumentException("Middleware's return type must implement " . RequestInterface::class);
        }

        // Check if two parameters are present
        $reflectionParams = $reflectionFunc->getParameters();
        if (count($reflectionParams) !== 2) {
            throw new \InvalidArgumentException("Middleware must accept two parameters");
        }

        // Check $request parameter
        $t = $reflectionParams[0]->getType();
        /** @var class-string */
        $requestType = empty($t) ? $t :
            throw new \InvalidArgumentException("Middleware's first parameter must implement " . RequestInterface::class);

        $requestTypeCls = new \ReflectionClass($requestType);
        if (!($requestTypeCls->implementsInterface(RequestInterface::class))) {
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

    protected function getServerPart(): string
    {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';

        $server = $_SERVER['HTTP_HOST'] ?? 'localhost';

        return $protocol . $server;
    }

    public function routeUrl(string $name, mixed ...$args): string
    {
        $route = $this->names[$name] ?? null;

        if ($route) {
            return $this->getServerPart() . $route->url(...$args);
        }

        throw new \RuntimeException('Route not found: ' . $name);
    }

    public function routeName(): ?string
    {
        return $this->params['name'] ?? null;
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

        return ($host ? trim($host, '/') : $this->getServerPart()) . $route['prefix'] . trim($path, '/');
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
                    throw new HttpInternalError(
                        $request,
                        "Controller method not found $view"
                    );
                }
            } else {
                throw new HttpInternalError(
                    $request,
                    "Controller not found ${ctrlName}"
                );
            }
        } else {
            throw new ValueError('Wrong view type');
        }
    }

    protected function respond(RouteInterface $route, RequestInterface $request): ResponseInterface
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

            throw new HttpInternalError(
                $request,
                "No renderer specified and view result is neither a response object nor a string."
            );
        }
    }

    public function dispatch(RequestInterface $request): ResponseInterface
    {
        $route = $this->match($request);

        if ($route) {
            $middlewares = array_merge($this->middlewares, $route->middlewares());

            while ($current = current($middlewares)) {
                $next = next($middlewares);

                if ($next !== false) {
                    $request = $current($request, $next);
                }
            }

            return $this->respond($route, $request);
        } else {
            throw new HttpNotFound($request);
        }
    }
}
