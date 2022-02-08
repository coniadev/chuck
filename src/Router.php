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


    public function dispatch(RequestInterface $request): ResponseInterface
    {
        $route = $this->match($request);

        if ($route) {
            $viewDef = $route->view();

            if (is_string($viewDef)) {
                $segments = explode('::', $viewDef);
                $ctrlName = $segments[0];
                $viewName = $segments[1];

                if (class_exists($ctrlName)) {
                    $ctrl = new $ctrlName($this->params);
                    $request->negotiateLocale($request);

                    if (!method_exists($ctrl, $viewName)) {
                        throw new HttpInternalError(
                            $request,
                            "Controller view method not found $ctrlName::$viewName"
                        );
                    }

                    $view = new ViewController($request, $route);
                    $view->addCallable($ctrl, $viewName);
                    return $view->call();
                } else {
                    throw new HttpInternalError(
                        $request,
                        "Controller not found $ctrlName"
                    );
                }
            } else {
                $view = new ViewFunction($request, $route);
                $view->addCallable($viewDef);
                return $view->call();
            }
        } else {
            throw new HttpNotFound($request);
        }
    }
}
