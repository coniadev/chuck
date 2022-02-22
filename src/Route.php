<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Util\Arrays;

const LEFT_BRACE = '§§§€§§§';
const RIGHT_BRACE = '§§§£§§§';


class Route implements RouteInterface
{
    protected array $args = [];
    protected array $methods = [];
    protected ?Renderer\Config $renderer = null;
    protected array $middlewares = [];

    public function __construct(
        protected string $name,
        protected string $route,
        protected string|\Closure $view,
        protected array $params = [],
    ) {
        $this->route = '/' . ltrim($route, '/');
    }

    public static function get(string $name, string $route, string|\Closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('GET');
    }

    public static function post(string $name, string $route, string|\Closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('POST');
    }

    public static function put(string $name, string $route, string|\Closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('PUT');
    }

    public static function patch(string $name, string $route, string|\Closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('PATCH');
    }

    public static function delete(string $name, string $route, string|\Closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('DELETE');
    }

    public static function head(string $name, string $route, string|\Closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('HEAD');
    }

    public static function options(string $name, string $route, string|\Closure $view, array $params = []): self
    {
        return (new self($name, $route, $view, $params))->method('OPTIONS');
    }

    public function method(string ...$args): self
    {
        $this->methods = array_merge($this->methods, array_map(fn ($m) => strtoupper($m), $args));

        return $this;
    }

    public function prefix(?string $prefix = null, ?string $name = null): self
    {
        if ($prefix) {
            $this->route = '/' . ltrim(rtrim($prefix, '/'), '/') . $this->route;
        }

        if ($name) {
            $this->name = $name . $this->name;
        }

        return $this;
    }

    public function render(string $renderer, mixed ...$args): self
    {
        $this->renderer = new Renderer\Config($renderer, $args);

        return $this;
    }

    public function getRenderer(): ?Renderer\Config
    {
        return $this->renderer;
    }

    public function middleware(callable $middleware): self
    {
        $this->middlewares[] = $middleware;

        return $this;
    }

    public function middlewares(): array
    {
        return $this->middlewares;
    }

    public function name(): string
    {
        return $this->name;
    }

    protected function hideInnerBraces(string $str): string
    {
        if (strpos($str, '\{') || strpos($str, '\}')) {
            throw new \ValueError('Escaped braces are not allowed: ' . $this->route);
        }

        $new = '';
        $level = 0;

        foreach (str_split($str) as $c) {
            if ($c === '{') {
                $level += 1;

                if ($level > 1) {
                    $new .= LEFT_BRACE;
                } else {
                    $new .= '{';
                }
                continue;
            }

            if ($c === '}') {
                if ($level > 1) {
                    $new .= RIGHT_BRACE;
                } else {
                    $new .= '}';
                }

                $level -= 1;
                continue;
            }

            $new .= $c;
        }

        if ($level !== 0) {
            throw  new \ValueError('Unbalanced braces in route pattern: ' . $this->route);
        }

        return $new;
    }

    protected function restoreInnerBraces(string $str): string
    {
        return str_replace(LEFT_BRACE, '{', str_replace(RIGHT_BRACE, '}', $str));
    }

    protected function pattern(): string
    {
        // escape forward slashes
        //     /evil/chuck  to \/evil\/chuck
        $pattern = preg_replace('/\//', '\\/', $this->route);

        $pattern = $this->hideInnerBraces($pattern);

        // convert variables to named group patterns
        //     /evil/{chuck}  to  /evil/(?P<chuck>[\w-]+)
        $pattern = preg_replace('/\{(\w+?)\}/', '(?P<\1>[\w-]+)', $pattern);

        // convert variables with custom patterns e.g. {evil:\d+}
        //     /evil/{chuck:\d+}  to  /evil/(?P<chuck>\d+)
        $pattern = preg_replace('/\{(\w+?):(.+?)\}/', '(?P<\1>\2)', $pattern);

        // convert remainder pattern ...slug to (?P<slug>.*)
        $pattern = preg_replace('/\.\.\.(\w+?)$/', '(?P<\1>.*)', $pattern);

        $pattern = '/^' . $pattern . '$/';

        return $this->restoreInnerBraces($pattern);
    }

    public function url(mixed ...$args): string
    {
        if (count($args) > 0) {
            if (is_array($args[0] ?? null)) {
                $args = $args[0];
            } else {
                if (!Arrays::isAssoc($args)) {
                    throw new \InvalidArgumentException(
                        'Route::url: either pass an associative array or named arguments'
                    );
                }
            }

            $url = $this->route;

            foreach ($args as $name => $value) {
                // basic variables
                $url = preg_replace(
                    '/\{' . $name . '(:.*?)?\}/',
                    urlencode((string)$value),
                    $url,
                );

                // remainder variables
                $url = preg_replace(
                    '/\.\.\.' . $name . '/',
                    urlencode((string)$value),
                    $url,
                );
            }

            return $url;
        }

        return $this->route;
    }

    public function view(): string|\Closure
    {
        return $this->view;
    }

    public function args(): array
    {
        return $this->args;
    }

    protected function removeQueryString(string $url): string
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
        $url = $this->removeQueryString($_SERVER['REQUEST_URI']);

        if (preg_match($this->pattern(), $url, $matches)) {
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
