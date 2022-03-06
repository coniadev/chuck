<?php

declare(strict_types=1);

namespace Chuck\Template;

use \RuntimeException;
use \ValueError;
use Chuck\Util\Path;


class Engine extends TemplateEngine
{
    protected array $captured;
    protected array $sections;

    public function __construct(protected array $dirs, protected array $defaults = [])
    {
    }

    public function render(string $moniker, array $context = []): string
    {
        if (empty($moniker)) {
            throw new \InvalidArgumentException('No template path given');
        }

        $error = null;
        $path = $this->getPath($moniker);

        $load =  function (string $templatePath, array $context = []): void {
            // Hide $templatePath. Could be overwritten if $context['templatePath'] exists.
            $____template_path____ = $templatePath;

            extract($context);

            /** @psalm-suppress UnresolvableInclude */
            include $____template_path____;
        };

        $template = new Template($this, $moniker, $context);
        $load = $load->bindTo($template);

        if (!$load) {
            throw new RuntimeException('Unable to bind context to template');
        }

        ob_start();

        try {
            $load($path, $this->defaults);
        } catch (\Throwable $e) {
            $error = $e;
        }

        $content = ob_get_contents();
        ob_end_clean();

        if ($template->hasLayout()) {
            $layout = $template->getLayout();
            $context[$this->getBodyId($layout)] = $content;
            $content = $this->render($layout, $context);
        }

        if ($error === null) {
            return $content;
        }

        throw $error;
    }

    public function getBodyId(string $moniker): string
    {
        return hash('xxh32', $moniker);
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

    public function beginSection($name): void
    {
        $this->capture[] = $name;
        ob_start();
    }

    public function endSection(): void
    {
        $content = ob_get_clean();
        $name = array_pop($this->capture);
        $this->sections[$name] = $content;
    }

    public function getSection(string $name): string
    {
        return $this->sections[$name];
    }
}
