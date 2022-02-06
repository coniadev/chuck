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


    protected function removeQueryString($url): string
    {
        return strtok($url, '?');
    }

    public function add(
        string $name,
        string $route,
        string|callable $view,
        array $params = [],
    ): void {
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

    protected function isMethod($allowed): bool
    {
        return strtoupper($_SERVER['REQUEST_METHOD']) === strtoupper($allowed);
    }

    protected function checkMethod(array $params): bool
    {
        if (array_key_exists('method', $params)) {
            $allowed = $params['method'];

            if (gettype($allowed) === 'string') {
                if ($this->isMethod($allowed)) {
                    return true;
                }
            } else {
                foreach ($allowed as $method) {
                    if ($this->isMethod($method)) {
                        return true;
                    }
                }
            }

            return false;
        }

        return true;
    }

    public function match(RequestInterface $request): ?Route
    {
        $url = $this->removeQueryString($request->url());
        $requestMethod = strtolower($request->method());

        foreach ($this->routes as $route) {
            if (preg_match($route->pattern, $url, $matches)) {
                $args = [];

                foreach ($matches as $key => $match) {
                    $args[$key] = $match;
                }

                if (count($args) > 0) {
                    $route->addArgs($args);
                }

                if ($this->checkMethod($route, $requestMethod)) {
                    $route->addUrl($url);

                    return $route;
                }
            }
        }

        return null;
    }


    public function dispatch(App $app): ResponseInterface
    {
        $request = $app->getRequest();
        $route = $this->match($request);

        if ($route) {
            $viewDef = $route->view();

            if (is_string($viewDef)) {
                $segments = explode('::', $viewDef);
                $ctrlName = $segments[0];
                $viewName = $segments[1];

                if (class_exists($ctrlName)) {
                    $ctrl = new $ctrlName($this->params);
                    $app->negotiateLocale($request);

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
