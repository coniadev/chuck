<?php

declare(strict_types=1);

namespace Conia\Chuck\Routing;

use Closure;
use InvalidArgumentException;
use ValueError;
use Conia\Chuck\Util\Arrays;
use Conia\Chuck\Renderer\Config as RendererConfig;

const LEFT_BRACE = '§§§€§§§';
const RIGHT_BRACE = '§§§£§§§';


class Route implements RouteInterface
{
    protected string $name;
    protected array $args = [];
    protected array $methods = [];
    protected ?RendererConfig $renderer = null;
    protected array $middlewares = [];


    /**
     * @param $pattern The URL pattern of the route.
     * @param $view The callable view. Can be a closure, an invokable object or any other callable
     * @param $name The name of the route. If not given the pattern will be hashed and used as name.
     * @param $params Optional arry which is stored alongside the route that can be consumed in the app
     */
    public function __construct(
        protected string $pattern,
        /** @property Closure|list{string, string}|string */
        protected Closure|array|string $view,
        ?string $name = null,
        protected array $params = [],
    ) {
        if ($name) {
            $this->name = $name;
        } else {
            $this->name = $this->pattern;
        }
    }

    public static function get(
        string $pattern,
        /** @property Closure|list{string, string}|string */
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): static {
        return (new self($pattern, $view, $name, $params))->method('GET');
    }

    public static function post(
        string $pattern,
        /** @property Closure|list{string, string}|string */
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): static {
        return (new self($pattern, $view, $name, $params))->method('POST');
    }

    public static function put(
        string $pattern,
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): static {
        return (new self($pattern, $view, $name, $params))->method('PUT');
    }

    public static function patch(
        string $pattern,
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): static {
        return (new self($pattern, $view, $name, $params))->method('PATCH');
    }

    public static function delete(
        string $pattern,
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): static {
        return (new self($pattern, $view, $name, $params))->method('DELETE');
    }

    public static function head(
        string $pattern,
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): static {
        return (new self($pattern, $view, $name, $params))->method('HEAD');
    }

    public static function options(
        string $pattern,
        Closure|array|string $view,
        ?string $name = null,
        array $params = []
    ): static {
        return (new self($pattern, $view, $name, $params))->method('OPTIONS');
    }

    public function method(string ...$args): static
    {
        $this->methods = array_merge($this->methods, array_map(fn ($m) => strtoupper($m), $args));

        return $this;
    }

    public function methods(): array
    {
        return $this->methods;
    }

    public function prefix(string $pattern = '', string $name = ''): static
    {
        if (!empty($pattern)) {
            $this->pattern = $pattern . $this->pattern;
        }

        if (!empty($name)) {
            $this->name = $name . $this->name;
        }

        return $this;
    }

    public function render(string $renderer, mixed ...$args): static
    {
        $this->renderer = new RendererConfig($renderer, $args);

        return $this;
    }

    public function getRenderer(): ?RendererConfig
    {
        return $this->renderer;
    }


    public function replaceMiddleware(callable|string ...$middlewares): static
    {
        $this->middlewares = $middlewares;

        return $this;
    }

    public function middleware(callable|string ...$middlewares): static
    {
        foreach ($middlewares as $middleware) {
            $this->middlewares[] = $middleware;
        }

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
            throw new ValueError('Escaped braces are not allowed: ' . $this->pattern);
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
            throw  new ValueError('Unbalanced braces in route pattern: ' . $this->pattern);
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
                // Check if args is an associative array
                if (array_keys($args) === range(0, count($args) - 1)) {
                    throw new InvalidArgumentException(
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

    /** @return Closure|string|list{string, string} */
    public function view(): Closure|array|string
    {
        return $this->view;
    }

    public function args(): array
    {
        return $this->args;
    }

    public function match(string $url): ?Route
    {
        if (preg_match($this->pattern(), $url, $matches)) {
            // Remove integer indexes from array
            $matches = array_filter(
                $matches,
                fn ($_, $k) => !is_int($k),
                ARRAY_FILTER_USE_BOTH
            );

            foreach ($matches as $key => $match) {
                $this->args[$key] = $match;
            }

            return $this;
        }

        return null;
    }
}
