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
        if (array_key_exists($name, $this->names)) {
            throw new \ErrorException('Duplicate route name: ' . $name);
        }

        $route = new Route($route, $view, $params);
        $this->routes[] = $route;
        $this->names[$name] = $route;
    }

    public function addStatic(
        string $name,
        string $prefix,
        bool $cacheBusting = false
    ) {
        $this->staticRoutes[$name] = [
            'path' => '/' . trim($prefix, '/') . '/',
            'bust' => $cacheBusting,
        ];
    }

    protected function getServerPart(): string
    {
        $protocol = (!empty($_SERVER['HTTPS']) &&
            (strtolower($_SERVER['HTTPS']) == 'on' || $_SERVER['HTTPS'] == '1')) ? 'https://' : 'http://';

        $server = $_SERVER['HTTP_HOST'] ?? 'localhost';

        return $protocol . $server;
    }

    public function routeUrl(string $name, array $args): string
    {
        $route = $this->names[$name] ?? null;

        if ($route) {
            return
                $this->getServerPart() .
                $route->replaceParams($args);
        }

        throw new \RuntimeException('Route not found: ' . $name);
    }

    public function routeName(): ?string
    {
        return $this->params['name'] ?? null;
    }

    protected function getCacheBuster(string $url): string
    {
        $sep = strpos($url, '?') === false ? '?' : '&';
        return $url . $sep . 'v=' . substr(md5(APP_VERSION), 0, 6);
    }

    public function staticUrl(string $name, string $path): string
    {
        $route = $this->staticRoutes[$name];
        $url = $this->getServerPart() . $route['path'] . trim($path, '/');

        if ($route['bust']) {
            $url = $this->getCacheBuster($url);
        }

        return $url;
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
