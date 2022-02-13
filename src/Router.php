<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpNotFound;
use Chuck\Exception\HttpInternalError;


class Router implements RouterInterface
{
    protected array $routes = [];
    protected array $staticRoutes = [];
    public array $params = [];
    protected array $names = [];
    protected string $responseClass = Response::class;
    protected string $templateRenderer = Renderer\TemplateRenderer::class;
    protected array $renderers = [
        'string' => Renderer\StringRenderer::class,
        'json' => Renderer\JsonRenderer::class,
    ];
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
    ) {
        if (is_dir($dir)) {
            $this->staticRoutes[$name] = [
                'prefix' => '/' . trim($prefix, '/') . '/',
                'dir' => $dir,
            ];
        } else {
            throw new \InvalidArgumentException("The static directory does not exist: $dir");
        }
    }

    public function setResponseClass(string $class): void
    {
        $this->responseClass = $class;
    }

    public function getResponseClass(): string
    {
        return $this->responseClass;
    }

    public function setRenderer(string $name, string $class): void
    {
        if (strtolower($name) === 'template') {
            $this->templateRenderer = $class;
        } else {
            $this->renderers[$name] = $class;
        }
    }

    public function renderer(string $name): string
    {
        if (strtolower($name) === 'template') {
            return $this->templateRenderer;
        } else {
            return $this->renderers[$name];
        }
    }

    public function middleware(callable $middleware): void
    {
        $this->middlewares[] = $middleware;
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

    public function staticUrl(string $name, string $path, bool $bust = false, string $host = null): string
    {
        $route = $this->staticRoutes[$name];

        if ($bust) {
            // Check if there is already a query parameter present
            if (strpos($path, '?')) {
                $file = strtok($path, '?');
                print("$file\n");
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
        } else {
            if (is_string($view) && !str_contains($view, '::')) {
                $view .= '::__invoke';
            }

            [$ctrlName, $method] = explode('::', $view);

            if (class_exists($ctrlName)) {
                $ctrl = new $ctrlName($this->request);

                if (method_exists($ctrl, 'method')) {
                    return $ctrl->$method($request);
                } else {
                    throw new HttpInternalError(
                        $this->request,
                        "Controller method not found $view"
                    );
                }
            } else {
                throw new HttpInternalError(
                    $this->request,
                    "Controller not found ${ctrlName}"
                );
            }
        }
    }

    protected function respond(RouteInterface $route, RequestInterface $request): ResponseInterface
    {
        $result = $this->getViewResult($route, $request);

        if ($result instanceof ResponseInterface) {
            return $result;
        } else {
            $body = $this->body;
            $renderer = $route->getRenderer();

            if ($renderer) {
                if (array_key_exists($this->renderers, $renderer) {
                    $rendererObj = new $this->renderers[$renderer]($this->request, $body);

                    $response = new Response(
                foreach ($rendererObj->headers() as $header) {
                    $this->addHeader($header['name'], $header['value']);
                }
            }

            throw new HttpInternalError(
                $this->request,
                "No response object returned and no renderer specified"
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
