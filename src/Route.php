<?php

declare(strict_types=1);

namespace Chuck;

class Route
{
    protected array $args;
    protected string $pattern;

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
        $this->methods = array_map(fn ($m) => strtoupper($m), $args);

        return $this;
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

    public function getUrl(...$args): string
    {
        if (count($args) > 0) {
            foreach ($args as $name => $value) {
                // basic variables
                $route =  preg_replace(
                    '/\{' . $name . '(:.*?)?\}/',
                    (string)$value,
                    $this->route
                );

                // remainder variables
                $route =  preg_replace(
                    '/\.\.\.' . $name . '/',
                    (string)$value,
                    $route
                );
            }
        }

        return $this->route;
    }

    public function view(): string|\closure
    {
        return $this->view;
    }

    public function pattern(): string
    {
        return $this->pattern;
    }

    public function params(): array
    {
        return array_replace_recursive(
            [
                'path' => null,
                'name' => null,
                'route' => null,
                'view' => null,
                'permission' => null,
                'renderer' => null,
                'csrf' => true,
                'csrf_page' => 'default',
            ],
            $this->params,
        );
    }

    public function addArgs(array $args): void
    {
        $this->params['args'] = $args;
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
        if (array_key_exists('method', $this->params)) {
            $allowed = $this->params['method'];

            if (is_array($allowed)) {
                foreach ($allowed as $method) {
                    if ($this->isMethodAllowed($request, $method)) {
                        return true;
                    }
                }
            } else {
                if ($this->isMethodAllowed($request, $allowed)) {
                    return true;
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

        if (preg_match($this->pattern, $url, $matches)) {
            $args = [];

            foreach ($matches as $key => $match) {
                $args[$key] = $match;
            }

            if (count($args) > 0) {
                $this->addArgs($args);
            }

            if ($this->checkMethod($request)) {
                $this->params['url'] = $url;

                return $this;
            }
        }

        return null;
    }
}
