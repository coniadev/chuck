<?php

declare(strict_types=1);

namespace Chuck;

class Request implements RequestInterface
{
    public $rolefinder = null;
    public ConfigInterface $config;
    public SessionInterface $session;

    protected RouterInterface $router;
    protected array $customMethods = [];

    public function __construct(ConfigInterface $config, RouterInterface $router)
    {
        $this->router = $router;
        $this->config = $config;

        $class = $this->config->di('Session');
        $this->session = new $class($this);
    }

    public function matchdict(string $key, ?string $default = null): ?string
    {
        if (func_num_args() > 1) {
            return $this->router->params['args'][$key] ?? $default;
        }

        return $this->router->params['args'][$key];
    }

    public function getMatchdict(): array
    {
        return $this->router->params['args'];
    }

    public function params(): array
    {
        return array_merge($_GET, $_POST);
    }
    public function param(string $key, ?string $default = null): null|string|array
    {
        if (array_key_exists($key, $_POST)) {
            return $_POST[$key];
        }

        if (array_key_exists($key, $_GET)) {
            return $_GET[$key];
        }

        if (func_num_args() > 1) {
            return $default;
        }

        return null;
    }

    public function routeUrl(string $name, array $args = []): string
    {
        return $this->router->routeUrl($name, $args);
    }

    public function routeName(): ?string
    {
        return $this->router->routeName();
    }

    public function staticUrl(string $name, string $path): string
    {
        return $this->router->staticUrl($name, $path);
    }

    public function url(): string
    {
        return $_SERVER['REQUEST_URI'];
    }

    public function serverUrl()
    {
        $serverName = $_SERVER['SERVER_NAME'];

        if (!in_array($_SERVER['SERVER_PORT'], [80, 443])) {
            $port = ":$_SERVER[SERVER_PORT]";
        } else {
            $port = '';
        }

        if (!empty($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) == 'on' || $_SERVER['HTTPS'] == '1')) {
            $scheme = 'https';
        } else {
            $scheme = 'http';
        }

        return $scheme . '://' . $serverName . $port;
    }

    public function isXHR(): bool
    {
        return (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
    }

    /**
     * Returns the path without query string
     */
    public function urlPath(): string
    {
        return trim(strtok($_SERVER['REQUEST_URI'], '?'));
    }

    public function redirect(string $url, int $code = 302): ResponseInterface
    {
        $class = $this->config->di('Response');
        $response = new $class($this);
        $response->addHeader('Location', $url, true, $code);
        return $response;
    }

    public function redirectToRemembered(int $code = 302): ResponseInterface
    {
        return $this->redirect($this->session->returnTo(), $code);
    }

    public function getRouter(): RouterInterface
    {
        return $this->router;
    }

    public function getRoute(): array
    {
        return $this->router->params;
    }

    public function flash(string $type, string $message): void
    {
        $this->session->flash($type, $message);
    }

    public function popFlash(): array
    {
        return $this->session->popFlash();
    }

    public function hasFlashes(): bool
    {
        return $this->session->hasFlashes();
    }

    public function permissions(): array
    {
        static $permissions = false;

        if ($permissions !== false) {
            return $permissions;
        }

        $auth = $this->config->di('Auth');

        if (!$auth) {
            return [];
        }

        $permissions = $auth::permissions();
        return $permissions;
    }

    public function user(): ?array
    {
        $auth = $this->config->di('Auth');

        if (!$auth) {
            return null;
        }

        return $auth::user();
    }

    public function method(): string
    {
        return strtoupper($_SERVER['REQUEST_METHOD']);
    }

    public function contentType(): string
    {
        return $_SERVER['CONTENT_TYPE'];
    }

    public function isMethod(string $method): bool
    {
        return strtoupper($method) === $this->method();
    }

    public function devel(): bool
    {
        return $this->config->get('devel');
    }

    public function production(): bool
    {
        return !$this->config->get('devel');
    }

    public function jsonBody(): ?array
    {
        static $json = null;

        if ($json === null) {
            // Get JSON as a string
            $jsonStr = file_get_contents('php://input');
            $json = json_decode($jsonStr, true);
        }

        return $json;
    }

    public function addRequestMethod(string $name, \Closure $func): void
    {
        $this->customMethods[$name] = $func;
    }

    public function __call(string $name, array $args)
    {
        $func = $this->customMethods[$name];
        return $func->call($this, ...$args);
    }
}