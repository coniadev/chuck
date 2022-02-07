<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Util\Arrays;

class Route
{
    protected array $args = [];
    protected string $pattern;
    protected array $methods = [];

    public function __construct(
        protected string $name,
        protected string $route,
        protected string|\closure $view,
        protected array $params = [],
    ) {
        $this->pattern = $this->convertToRegex($route);
    }

    public static function get(string $name, string $route, string|\closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('GET');
    }

    public static function post(string $name, string $route, string|\closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('POST');
    }

    public static function put(string $name, string $route, string|\closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('PUT');
    }

    public static function patch(string $name, string $route, string|\closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('PATCH');
    }

    public static function delete(string $name, string $route, string|\closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('DELETE');
    }

    public static function head(string $name, string $route, string|\closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('HEAD');
    }

    public static function options(string $name, string $route, string|\closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('OPTIONS');
    }

    public function method(string ...$args): self
    {
        $this->methods = array_merge($this->methods, array_map(fn ($m) => strtoupper($m), $args));

        return $this;
    }

    protected function convertToRegex(string $route): string
    {
        // escape forward slashes
        //     /evil/chuck  to \/evil\/chuck
        $pattern = preg_replace('/\//', '\\/', $route);

        // convert variables to named group patterns
        //     /evil/{chuck}  to  /evil/(?P<evil>[\w-]+)
        $pattern = preg_replace('/\{(\w+?)\}/', '(?P<\1>[\w-]+)', $pattern);

        // convert variables with custom patterns e.g. {evil:\d+}
        //     /evil/{chuck:\d+}  to  /evil/(?P<evil>\d+)
        // TODO: support length ranges: {evil:\d{1,3}}
        $pattern = preg_replace('/\{(\w+?):(.+?)\}/', '(?P<\1>\2)', $pattern);

        // convert remainder pattern ...slug to (?P<slug>.*)
        $pattern = preg_replace('/\.\.\.(\w+?)$/', '(?P<\1>.*)', $pattern);

        $pattern = '/^' . $pattern . '$/';

        return $pattern;
    }

    public function getUrl(...$args): string
    {
        if (count($args) > 0) {
            if (is_array($args[0] ?? null)) {
                $args = $args[0];
            } else {
                if (!Arrays::isAssoc($args)) {
                    throw new \InvalidArgumentException(
                        'Route::getUrl: either pass an associative array or named arguments'
                    );
                }
            }

            $url = $this->route;

            foreach ($args as $name => $value) {
                // basic variables
                $url = preg_replace(
                    '/\{' . $name . '(:.*?)?\}/',
                    (string)$value,
                    $url
                );

                // remainder variables
                $url = preg_replace(
                    '/\.\.\.' . $name . '/',
                    (string)$value,
                    $url
                );
            }

            return $url;
        }

        return $this->route;
    }

    public function view(): string|\closure
    {
        return $this->view;
    }

    public function args(): array
    {
        return $this->args;
    }

    protected function removeQueryString($url): string
    {
        return strtok($url, '?');
    }

    protected function isMethodAllowed(RequestInterface $request, string $allowed): bool
    {
        return strtoupper($request->method()) === strtoupper($allowed);
    }

    protected function checkMethod(RequestInterface $request): bool
    {
        if (count($this->methods) === 0) {
            return true;
        }

        foreach ($this->methods as $method) {
            if ($this->isMethodAllowed($request, $method)) {
                return true;
            }
        }

        return false;
    }

    public function match(RequestInterface $request): ?Route
    {
        $url = $this->removeQueryString($request->url());

        if (preg_match($this->pattern, $url, $matches)) {
            // Remove integer indexes from array
            $matches = array_filter($matches, fn ($_, $k) => !is_int($k), ARRAY_FILTER_USE_BOTH);

            foreach ($matches as $key => $match) {
                $this->args[$key] = $match;
            }

            if ($this->checkMethod($request)) {
                return $this;
            }
        }

        return null;
    }
}
