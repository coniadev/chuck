<?php

declare(strict_types=1);

namespace Chuck;

class Request implements RequestInterface
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected readonly ResponseInterface $response;

    protected readonly RouterInterface $router;
    protected readonly ConfigInterface $config;
    protected array $customMethods = [];

    public function __construct(
        ConfigInterface $config,
        RouterInterface $router,
    ) {
        $this->router = $router;
        $this->config = $config;
    }

    public function matchdict(string $key, ?string $default = null): ?string
    {
        $matchdict = $this->router->getRoute()->args();

        if (func_num_args() > 1) {
            return $matchdict[$key] ?? $default;
        }

        return $matchdict[$key];
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

    public function staticUrl(string $name, string $path): string
    {
        return $this->router->staticUrl($name, $path);
    }

    public function url(): string
    {
        return $_SERVER['REQUEST_URI'];
    }

    public function serverUrl(): string
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
        $class = $this->config->registry(ResponseInterface::class);
        /** @var ResponseInterface */
        $response = new $class($this, statusCode: $code);
        $response->addHeader('Location', $url, true);
        return $response;
    }

    public function getRoute(): Route
    {
        return $this->router->getRoute();
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

    public function debug(): bool
    {
        return $this->config->get('debug');
    }

    public function env(): string
    {
        return $this->config->get('env');
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


    /**
     * Adds a custom method to the request which can be used
     * in views and middlewares, like $request->customMethod().
     */
    public function addMethod(string $name, callable $callable): void
    {
        $this->customMethods[$name] = $callable;
    }

    public function getRouter(): RouterInterface
    {
        return $this->router;
    }

    public function getConfig(): ConfigInterface
    {
        return $this->config;
    }

    public function getResponse(
        int $statusCode = 200,
        mixed $body = null,
        array $headers = [],
        ?string $protocol = null,
        ?string $reasonPhrase = null,
    ): ResponseInterface {
        /** @psalm-suppress RedundantPropertyInitializationCheck */
        if (!isset($this->response)) {
            /**
             * @psalm-suppress InaccessibleProperty
             * @var ResponseInterface
             *
             * TODO: At the time of writing Psalm did not support
             * readonly properties which are not initialized in the
             * constructor. Recheck on occasion.
             */
            $this->response = new ($this->config->registry(ResponseInterface::class))($this);
        }

        $this->response->setStatusCode($statusCode, $reasonPhrase);

        if ($body) {
            $this->response->setBody($body);
        }

        foreach ($headers as $header) {
            $this->response->addHeader(
                $header['name'],
                $header['value'],
                $header['replace'] ?? true
            );
        }

        if ($protocol) {
            $this->response->setProtocol($protocol);
        }

        return $this->response;
    }

    public function __call(string $name, array $args)
    {
        $func = $this->customMethods[$name];

        return $func->call($this, ...$args);
    }

    public function __get(string $key): ResponseInterface | ConfigInterface | RouterInterface
    {
        return match ($key) {
            /** @var ResponseInterface */
            'response' => $this->getResponse(),
            /** @var ConfigInterface */
            'config' => $this->config,
            /** @var RouterInterface */
            'router' => $this->router,
            default => throw new \ErrorException("Undefined property \"$key\"")
        };
    }
}
