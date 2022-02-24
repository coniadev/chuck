<?php

declare(strict_types=1);

namespace Chuck\Routing;

use \Closure;
use \ValueError;

use Chuck\Util\Arrays;
use Chuck\RequestInterface;
use Chuck\Renderer;

const LEFT_BRACE = '§§§€§§§';
const RIGHT_BRACE = '§§§£§§§';


class Route implements RouteInterface
{
    protected array $args = [];
    protected array $methods = [];
    protected ?Renderer\Config $renderer = null;
    protected array $middlewares = [];
    protected Closure|string $view;


    /**
     * @param $name The name of the route
     * @param $pattern The URL pattern of the route.
     * @param $view The callable view. Can be a closure, an invokable object or any other callable
     * @param $params Optional arry which is stored alongside the route that can be consumed in the app
     */
    public function __construct(
        protected string $name,
        protected string $pattern,
        callable|string $view,
        protected array $params = [],
    ) {
        if (is_callable($view)) {
            $this->view = Closure::fromCallable($view);
        } else {
            $this->view = $view;
        }
    }

    public static function get(string $name, string $pattern, callable|string $view, array $params = []): self
    {
        return (new self($name, $pattern, $view, $params))->method('GET');
    }

    public static function post(string $name, string $pattern, callable|string $view, array $params = []): self
    {
        return (new self($name, $pattern, $view, $params))->method('POST');
    }

    public static function put(string $name, string $pattern, callable|string $view, array $params = []): self
    {
        return (new self($name, $pattern, $view, $params))->method('PUT');
    }

    public static function patch(string $name, string $pattern, callable|string $view, array $params = []): self
    {
        return (new self($name, $pattern, $view, $params))->method('PATCH');
    }

    public static function delete(string $name, string $pattern, callable|string $view, array $params = []): self
    {
        return (new self($name, $pattern, $view, $params))->method('DELETE');
    }

    public static function head(string $name, string $pattern, callable|string $view, array $params = []): self
    {
        return (new self($name, $pattern, $view, $params))->method('HEAD');
    }

    public static function options(string $name, string $pattern, callable|string $view, array $params = []): self
    {
        return (new self($name, $pattern, $view, $params))->method('OPTIONS');
    }

    public function method(string ...$args): self
    {
        $this->methods = array_merge($this->methods, array_map(fn ($m) => strtoupper($m), $args));

        return $this;
    }

    public function prefix(string $name = '', string $pattern = ''): self
    {
        if (!empty($name)) {
            $this->name = $name . $this->name;
        }

        if (!empty($pattern)) {
            $this->pattern = $pattern . $this->pattern;
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

    public function middleware(callable|string ...$middlewares): self
    {
        $this->middlewares = $middlewares;

        return $this;
    }

    public function middlewares(): array
    {
        return $this->middlewares;
    }

    /**
     * Simply prefixes the current $this->view string with $controller
     */
    public function controller(string $controller): void
    {
        if (is_string($this->view)) {
            $this->view = $controller . $this->view;
        } else {
            throw new ValueError('Cannot add controller to view of type Closure');
        }
    }

    public function name(): string
    {
        return $this->name;
    }

    public function params(): array
    {
        return $this->params;
    }

    protected function hideInnerBraces(string $str): string
    {
        if (strpos($str, '\{') || strpos($str, '\}')) {
            throw new \ValueError('Escaped braces are not allowed: ' . $this->pattern);
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
            throw  new \ValueError('Unbalanced braces in route pattern: ' . $this->pattern);
        }

        return $new;
    }

    protected function restoreInnerBraces(string $str): string
    {
        return str_replace(LEFT_BRACE, '{', str_replace(RIGHT_BRACE, '}', $str));
    }

    protected function pattern(): string
    {
        // Ensure leading slash
        $pattern = '/' . ltrim($this->pattern, '/');

        // Escape forward slashes
        //     /evil/chuck  to \/evil\/chuck
        $pattern = preg_replace('/\//', '\\/', $pattern);

        $pattern = $this->hideInnerBraces($pattern);

        // Convert variables to named group patterns
        //     /evil/{chuck}  to  /evil/(?P<chuck>[\w-]+)
        $pattern = preg_replace('/\{(\w+?)\}/', '(?P<\1>[.\w-]+)', $pattern);

        // Convert variables with custom patterns e.g. {evil:\d+}
        //     /evil/{chuck:\d+}  to  /evil/(?P<chuck>\d+)
        $pattern = preg_replace('/\{(\w+?):(.+?)\}/', '(?P<\1>\2)', $pattern);

        // Convert remainder pattern ...slug to (?P<slug>.*)
        $pattern = preg_replace('/\.\.\.(\w+?)$/', '(?P<\1>.*)', $pattern);

        $pattern = '/^' . $pattern . '$/';

        return $this->restoreInnerBraces($pattern);
    }

    public function url(mixed ...$args): string
    {
        $url = '/' . ltrim($this->pattern, '/');

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
        }

        return $url;
    }

    public function view(): callable|string
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
