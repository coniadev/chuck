<?php

declare(strict_types=1);

namespace Chuck\Template;

use \InvalidArgumentException;
use \Throwable;
use Chuck\Error\{InvalidTemplateFormat, TemplateNotFound};
use Chuck\Util\Path;


class Engine
{
    protected array $capture = [];
    protected array $sections = [];

    public function __construct(protected array $dirs, protected array $defaults = [])
    {
    }

    public function render(string $moniker, array $context = []): string
    {
        if (empty($moniker)) {
            throw new InvalidArgumentException('No template path given');
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

        $template = $this->createTemplate($moniker, array_merge($this->defaults, $context));

        /** @var callable */
        $load = $load->bindTo($template);

        ob_start();

        try {
            $load($path, $template->context());
        } catch (Throwable $e) {
            $error = $e;
        }

        $content = ob_get_contents();
        ob_end_clean();

        if ($error !== null) {
            throw $error;
        }

        if ($template->hasLayout()) {
            $layout = $template->getLayout();
            $context[$this->getBodyId($layout)] = $content;
            $content = $this->render($layout, $context);
        }

        return $content;
    }

    protected function createTemplate(string $moniker, array $context): Template
    {
        return new Template($this, $moniker, $context);
    }

    public function getBodyId(string $moniker): string
    {
        return hash('xxh3', $moniker);
    }

    protected function getPath(string $template): string
    {
        $segments = explode(':', $template);

        [$namespace, $file] = match (count($segments)) {
            1 => [null, $segments[0]],
            2 => [$segments[0], $segments[1]],
            default => throw new InvalidTemplateFormat(
                "Invalid template format: '$template'. Use 'namespace:template/path or template/path'."
            ),
        };

        $file = trim(strtr($file, '\\', '/'), '/');
        $ext = '';

        if (empty(pathinfo($file, PATHINFO_EXTENSION))) {
            $ext = '.php';
        }

        $ds = DIRECTORY_SEPARATOR;

        if ($namespace) {
            $path = Path::realpath($this->dirs[$namespace] . $ds . $file . $ext);

            if (is_file($path)) {
                return $path;
            }
        } else {
            foreach ($this->dirs as $dir) {
                $path = Path::realpath($dir . $ds . $file . $ext);

                if (is_file($path)) {
                    return $path;
                }
            }
        }

        throw new TemplateNotFound("Template '$template' not found");
    }

    public function exists(string $moniker): bool
    {
        try {
            $this->getPath($moniker);
            return true;
        } catch (TemplateNotFound) {
            return false;
        }
    }

    public function beginSection(string $name): void
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

    public function hasSection(string $name): bool
    {
        return isset($this->sections[$name]);
    }
}
