<?php

declare(strict_types=1);

namespace Core;

use Core\Exception\HttpNotFound;
use Core\Exception\HttpInternalError;
use Core\Exception\HttpForbidden;
use Core\Exception\HttpUnauthorized;

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

    protected function convertToRegex(string $route): string
    {
        // escape forward slashes
        //     /hans/franz  to \/hans\/franz
        $pattern = preg_replace('/\//', '\\/', $route);

        // convert variables to named group patterns
        //     /hans/{franz}  to  /hans/(?P<hans>[\w-]+)
        $pattern = preg_replace('/\{(\w+?)\}/', '(?P<\1>[\w-]+)', $pattern);

        // convert variables with custom patterns e.g. {hans:\d+}
        //     /hans/{franz:\d+}  to  /hans/(?P<hans>\d+)
        // TODO: support length ranges: {hans:\d{1,3}}
        $pattern = preg_replace('/\{(\w+?):(.+?)\}/', '(?P<\1>\2)', $pattern);

        // convert remainder pattern ...slug to (?P<slug>.*)
        $pattern = preg_replace('/\.\.\.(\w+?)$/', '(?P<\1>.*)', $pattern);

        $pattern = '/^' . $pattern . '$/';

        return $pattern;
    }

    protected function removeQueryString($url): string
    {
        return strtok($url, '?');
    }

    public function add(array $route): void
    {
        $name = $route['name'];

        if (array_key_exists($name, $this->names)) {
            throw new \ErrorException('Duplicate route name: ' . $name);
        }

        $route['pattern'] = $this->convertToRegex($route['route']);
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

    protected function replaceParams(string $route, array $args): string
    {
        foreach ($args as $name => $value) {
            // basic variables
            $route =  preg_replace(
                '/\{' . $name . '(:.*?)?\}/',
                (string)$value,
                $route
            );

            // remainder variables
            $route =  preg_replace(
                '/\.\.\.' . $name . '/',
                (string)$value,
                $route
            );
        }

        return $route;
    }

    public function routeUrl(string $name, array $args): string
    {
        $route = $this->names[$name] ?? null;

        if ($route) {
            return
                $this->getServerPart() .
                $this->replaceParams($route['route'], $args);
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

    public function match(RequestInterface $request): bool
    {
        $url = $this->removeQueryString($request->url());
        $requestMethod = strtolower($request->method());

        foreach ($this->routes as $route) {
            if (preg_match($route['pattern'], $url, $matches)) {
                $args = [];

                foreach ($matches as $key => $match) {
                    $args[$key] = $match;
                }

                if (count($args) > 0) {
                    $route['args'] = $args;
                }

                if ($this->checkMethod($route, $requestMethod)) {
                    $this->params = array_replace_recursive(
                        [
                            'path' => $url,
                            'name' => null,
                            'route' => null,
                            'view' => null,
                            'permission' => null,
                            'renderer' => null,
                            'csrf' => true,
                            'csrf_page' => 'default',
                        ],
                        $route,
                    );
                    return true;
                }
            }
        }

        return false;
    }

    protected function checkAndCall(
        Controller $ctrl,
        string $view,
        RequestInterface $request
    ): ResponseInterface {
        $session = $request->session;

        if ($ctrl->before($request)) {
            $response = $ctrl->$view($request);

            if ($response instanceof ResponseInterface) {
                return $ctrl->after($request, $response);
            } else {
                $renderer = $this->params['renderer'] ?? null;
                $class = $request->config->di('Response');

                return $ctrl->after(
                    $request,
                    new $class($request, $response, $renderer)
                );
            }
        } else {
            $auth = $request->config->di('Auth');
            if ($session->authenticatedUserId() || $auth::verifyJWT() || $auth::verifyApiKey()) {
                // User is authenticated but does not have the permissions
                throw new HttpForbidden($request);
            } else {
                if ($request->isXHR()) {
                    throw new HttpUnauthorized($request);
                } else {
                    // User needs to log in
                    $session->rememberReturnTo();
                    return $request->redirect($request->routeUrl('user:login'));
                }
            }
        }
    }

    public function dispatch(App $app): ResponseInterface
    {
        $request = $app->getRequest();

        if ($this->match($request)) {
            $segments = explode('::', $this->params['view']);
            $ctrlName = $segments[0];
            $view = $segments[1];

            if (class_exists($ctrlName)) {
                $ctrl = new $ctrlName($this->params);
                $app->negotiateLocale($request);

                if (!method_exists($ctrl, $view)) {
                    throw new HttpInternalError(
                        $request,
                        "Controller view method not found $ctrlName::$view"
                    );
                }

                return $this->checkAndCall($ctrl, $view, $request);
            } else {
                throw new HttpInternalError(
                    $request,
                    "Controller not found $ctrlName"
                );
            }
        } else {
            throw new HttpNotFound($request);
        }
    }
}
