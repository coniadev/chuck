<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Util\Http;


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

    public function params(): array
    {
        // GET parameters have priority
        return array_merge($_POST, $_GET);
    }

    public function param(string $key, ?string $default = null): null|string|array
    {
        // prefer GET parameters
        if (array_key_exists($key, $_GET)) {
            return $_GET[$key];
        }

        if (array_key_exists($key, $_POST)) {
            return $_POST[$key];
        }

        if (func_num_args() > 1) {
            return $default;
        }

        return null;
    }

    public function url(): string
    {
        return $_SERVER['REQUEST_URI'];
    }

    public function serverUrl(): string
    {
        return Http::origin() . $this->url();
    }

    /**
     * Returns the path without query string
     */
    public function urlPath(): string
    {
        return trim(strtok($this->url(), '?'));
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

    public function routeUrl(string $name, mixed ...$args): string
    {
        return Http::origin() . $this->router->routeUrl($name, ...$args);
    }

    public function staticUrl(string $name, string $path, bool $bust = false): string
    {
        return $this->getRouter()->staticUrl(
            $name,
            $path,
            host: Http::origin(),
            bust: $bust,
        );
    }

    public function method(): string
    {
        return strtoupper($_SERVER['REQUEST_METHOD']);
    }

    public function isMethod(string $method): bool
    {
        return strtoupper($method) === $this->method();
    }

    public function jsonBody(string $stream = 'php:://input'): ?array
    {
        if (PHP_SAPI !== 'cli' && func_num_args() > 0) {
            // @codeCoverageIgnoreStart
            throw new \InvalidArgumentException('Changing the stream is only allowed in cli SAPI');
            // @codeCoverageIgnoreEnd
        }

        // Get JSON as a string
        $jsonStr = file_get_contents($stream);
        print($jsonStr . "\n");
        $json = json_decode($jsonStr, true);

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

    public function __get(
        string $key
    ): ResponseInterface | ConfigInterface | RouterInterface | RouteInterface | bool | string {
        return match ($key) {
            /** @var ResponseInterface */
            'response' => $this->getResponse(),
            /** @var ConfigInterface */
            'config' => $this->config,
            /** @var RouterInterface */
            'router' => $this->router,
            /** @var RouteInterface */
            'route' => $this->router->getRoute(),
            /** @var string */
            'env' => $this->config->env(),
            /** @var bool */
            'debug' => $this->config->debug(),
            default => throw new \RuntimeException("Undefined request property '$key'")
        };
    }
}
