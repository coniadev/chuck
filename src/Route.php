<?php

declare(strict_types=1);

namespace Chuck;

class Route
{
    protected array $args;
    protected string $pattern;

    public function __construct(
        protected string $route,
        protected string|callable $view,
        protected array $params
    ) {
        $this->pattern = $this->convertToRegex($route);
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

    public function replaceParams(array $args): string
    {
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

        return $route;
    }

    public function view(): string|callable
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

    public function addUrl(string $url): void
    {
        $this->params['url'] = $url;
    }

    public function addArgs(array $args): void
    {
        $this->params['args'] = $args;
    }
}
