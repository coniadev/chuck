<?php

declare(strict_types=1);

namespace Chuck;

use \InvalidArgumentException;
use \RuntimeException;
use Chuck\Assets\Assets;
use Chuck\Routing\RouteInterface;
use Chuck\Routing\RouterInterface;
use Chuck\Util\Http;


class Request implements RequestInterface
{
    /** @psalm-suppress PropertyNotSetInConstructor */
    protected readonly ResponseInterface $response;
    protected array $customMethods = [];

    public function __construct(
        protected ConfigInterface $config,
        protected RouterInterface $router,
        protected RegistryInterface $registry,
    ) {
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

    public function redirect(string $url, int $code = 302): ResponseInterface
    {
        $class = $this->registry->get(ResponseInterface::class);
        /** @var ResponseInterface */
        $response = new $class($this, statusCode: $code);
        $response->header('Location', $url, true);
        return $response;
    }

    public function getRoute(): RouteInterface
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

    public function methodIs(string $method): bool
    {
        return strtoupper($method) === $this->method();
    }

    public function body(string $stream = 'php://input'): string
    {
        // TODO: Code to allow testing. Maybe code smell.
        //       Allows to overwrite the stream as php://input
        //       can not be populated. See if we can get rid of it.
        if (PHP_SAPI !== 'cli' && func_num_args() > 0) {
            // @codeCoverageIgnoreStart
            throw new InvalidArgumentException('Changing the stream is only allowed in cli SAPI');
            // @codeCoverageIgnoreEnd
        }

        return file_get_contents($stream);
    }

    public function json(
        string $stream = 'php:://input',
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

    public function getRouter(): RouterInterface
    {
        return $this->router;
    }

    public function getConfig(): ConfigInterface
    {
        return $this->config;
    }

    public function getRegistry(): RegistryInterface
    {
        return $this->registry;
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
            $this->response = $this->registry->new(ResponseInterface::class, $this);
        }

        $this->response->statusCode($statusCode, $reasonPhrase);

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

    public function getAssets(): Assets
    {
        return Assets::fromConfig($this->config);
    }

    public function __call(string $name, array $args)
    {
        $func = $this->customMethods[$name];

        return $func->call($this, ...$args);
    }

    public function __get(
        string $key
    ): ResponseInterface | ConfigInterface | RouterInterface |
    RouteInterface | RegistryInterface | Assets | bool | string {
        return match ($key) {
            /** @var ResponseInterface */
            'response' => $this->getResponse(),
            /** @var ConfigInterface */
            'config' => $this->config,
            /** @var RouterInterface */
            'router' => $this->router,
            /** @var RouteInterface */
            'route' => $this->router->getRoute(),
            /** @var RegistryInterface */
            'registry' => $this->registry,
            /** @var Assets */
            'assets' => $this->getAssets(),
            /** @var string */
            'env' => $this->config->env(),
            /** @var bool */
            'debug' => $this->config->debug(),
            default => throw new RuntimeException("Undefined request property '$key'")
        };
    }
}
