<?php

declare(strict_types=1);

namespace Chuck;

use \ValueError;
use Chuck\Util\Path;


class Template extends AbstractTemplate
{
    protected RequestInterface $request;
    protected readonly array $folders;
    protected Path $pathUtil;

    public function __construct(protected array $dirs, protected array $defaults = [])
    {
    }

    public function render(string $template, array $context = []): string
    {
        if (empty($template)) {
            throw new \InvalidArgumentException('No template path given');
        }

        $context = array_merge($this->defaults, $context);
        $error = null;
        $path = $this->getPath($template);

        ob_start();

        try {
            $this->load($path, $context);
        } catch (\Throwable $e) {
            $error = $e;
        }

        $content = ob_get_contents();
        ob_end_clean();

        if ($error === null) {
            return $content;
        }

        throw $error;
    }

    protected function getPath(string $template): string
    {
        $segments = explode(':', $template);

        [$namespace, $file] = match (count($segments)) {
            1 => [null, $segments[0]],
            2 => [$segments[0], $segments[1]],
            default => throw new ValueError(
                "Invalid template format: '$template'. Use 'namespace:template/path or template/path'."
            ),
        };

        $file = trim(strtr($file, '\\', '/'), '/');
        $ds = DIRECTORY_SEPARATOR;

        if ($namespace) {
            $path = Path::realpath($this->dirs[$namespace] . $ds . $file . '.php');
        } else {
            try {
                $path = Path::realpath(
                    $this->dirs['default'] . $ds . $file . '.php'
                );
            } catch (\Exception) {
                throw new ValueError("No default template directory present.");
            }
        }

        if (file_exists($path)) {
            return $path;
        }

        throw new ValueError("Template '$path' not found inside the project root directory");
    }

    protected static function load(string $template, array $context = []): void
    {
        // Hide $template. Could be overwritten if $context['template'] exists.
        $____template____ = $template;

        extract($context);

        /** @psalm-suppress UnresolvableInclude */
        include $____template____;
    }

    public function exists(string $template): bool
    {
        try {
            $path = $this->getPath($template);

            if (empty($path)) {
                return false;
            }

            return true;
        } catch (ValueError) {
            return false;
        }
    }
}
