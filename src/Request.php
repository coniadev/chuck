<?php

declare(strict_types=1);

namespace Conia\Chuck;

use OutOfBoundsException;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Routing\RouteInterface;
use Conia\Chuck\Routing\RouterInterface;
use Conia\Chuck\Renderer\RendererInterface;
use Conia\Chuck\Util\Uri;

readonly class Request implements RequestInterface
{
    public function __construct(
        protected ConfigInterface $config,
        protected RouterInterface $router,
        public ResponseFactory $response = new ResponseFactory(),
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

        throw new OutOfBoundsException("Key '$key' not found");
    }

    public function scheme(): string
    {
        return Uri::scheme();
    }

    public function origin(): string
    {
        return Uri::origin();
    }

    public function url(bool $stripQuery = false): string
    {
        return Uri::url($stripQuery);
    }

    public function host(bool $stripPort = false): string
    {
        return Uri::host($stripPort);
    }

    public function path(bool $stripQuery = false): string
    {
        return Uri::path($stripQuery);
    }

    public function redirect(string $url, int $code = 302): never
    {
        Uri::redirect($url, $code);
    }

    public function route(): RouteInterface
    {
        return $this->router->getRoute();
    }

    public function routeUrl(string $name, mixed ...$args): string
    {
        return Uri::origin() . $this->router->routeUrl($name, ...$args);
    }

    public function staticUrl(string $name, string $path, bool $bust = false): string
    {
        return $this->router()->staticUrl(
            $name,
            $path,
            host: Uri::origin(),
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

    public function body(string $stream = 'php://input'): string
    {
        return file_get_contents($stream);
    }

    public function json(
        string $stream = 'php://input',
        int $flags = JSON_OBJECT_AS_ARRAY,
    ): mixed {
        $body = $this->body($stream);

        if (empty($body)) {
            return null;
        }

        return json_decode(
            $body,
            true,
            512, // PHP default value
            $flags,
        );
    }

    public function hasFile(string $key): bool
    {
        return array_key_exists($key, $_FILES);
    }

    public function hasMultipleFiles(string $key): bool
    {
        return array_key_exists($key, $_FILES) && is_array($_FILES[$key]['error']);
    }

    public function file(string $key): File
    {
        return new File($_FILES[$key]);
    }

    /** @return list<File> */
    public function files(string $key): array
    {
        if (is_array($_FILES[$key]['error'])) {
            $files = [];
            foreach ($_FILES[$key]['error'] as $idx => $error) {
                $files[] = new File([
                    'tmp_name' => $_FILES[$key]['tmp_name'][$idx],
                    'name' => $_FILES[$key]['name'][$idx],
                    'size' => $_FILES[$key]['size'][$idx],
                    'type' => $_FILES[$key]['type'][$idx],
                    'error' => $error,
                ]);
            }
            return $files;
        }

        return [$this->file($key)];
    }

    public function router(): RouterInterface
    {
        return $this->router;
    }

    public function config(): ConfigInterface
    {
        return $this->config;
    }

    public function response(): ResponseFactory
    {
        return $this->response;
    }

    public function renderer(string $type, mixed ...$args): RendererInterface
    {
        return $this->config->renderer($this, $type, ...$args);
    }
}
