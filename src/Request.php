<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Response;
use Chuck\Routing\RouteInterface;
use Chuck\Routing\RouterInterface;
use Chuck\Util\Http;


class Request implements RequestInterface
{
    protected ResponseInterface $response;
    protected array $customMethods = [];

    public function __construct(
        protected ConfigInterface $config,
        protected RouterInterface $router,
        ResponseInterface $response = null,
    ) {
        $this->response = $response ?: new Response();
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

    public function url(bool $stripQuery = false): string
    {
        if ($stripQuery) {
            // Returns the path without query string
            return trim(strtok($_SERVER['REQUEST_URI'], '?'));
        }

        return $_SERVER['REQUEST_URI'];
    }

    public function serverUrl(bool $stripQuery = false): string
    {
        return Http::origin() . $this->url($stripQuery);
    }

    public function redirect(string $url, int $code = 302): never
    {
        Http::redirect($url, $code);
    }

    public function route(): RouteInterface
    {
        return $this->router->getRoute();
    }

    public function routeUrl(string $name, mixed ...$args): string
    {
        return Http::origin() . $this->router->routeUrl($name, ...$args);
    }

    public function staticUrl(string $name, string $path, bool $bust = false): string
    {
        return $this->router()->staticUrl(
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

    public function methodIs(string $method): bool
    {
        return strtoupper($method) === $this->method();
    }

    public function body(string $stream = 'php://input'): string
    {
        return file_get_contents($stream);
    }

    public function json(
        string $stream = 'php://input',
        int $flags = JSON_OBJECT_AS_ARRAY,
    ): mixed {
        $body = $this->body($stream);

        if (empty($body)) return null;

        return json_decode(
            $body,
            true,
            512, // PHP default value
            $flags,
        );
    }

    /**
     * Adds a custom method to the request which can be used
     * in views and middlewares, like $request->customMethod().
     */
    public function addMethod(string $name, callable $callable): void
    {
        $this->customMethods[$name] = $callable;
    }

    public function router(): RouterInterface
    {
        return $this->router;
    }

    public function config(): ConfigInterface
    {
        return $this->config;
    }

    public function response(
        int $statusCode = 200,
        mixed $body = null,
        /** @param array{name: string, value: string, replace: bool} */
        array $headers = [],
        ?string $protocol = null,
        ?string $reasonPhrase = null,
    ): ResponseInterface {
        $this->response->setStatusCode($statusCode, $reasonPhrase);

        if ($body) {
            $this->response->body($body);
        }

        foreach ($headers as $header) {
            $this->response->header(
                $header['name'],
                $header['value'],
                $header['replace'] ?? true
            );
        }

        if ($protocol) {
            $this->response->protocol($protocol);
        }

        return $this->response;
    }

    public function __call(string $name, array $args)
    {
        $func = $this->customMethods[$name];

        return $func->call($this, ...$args);
    }
}
