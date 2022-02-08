<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpInternalError;


class ViewController extends View
{
    protected object $ctrl;
    protected string $method;

    protected function init(): void
    {
        $view = $this->view;

        if (is_string($view) && !str_contains($view, '::')) {
            $view .= '::__invoke';
        }

        [$ctrlName, $method] = explode('::', $view);

        if (class_exists($ctrlName)) {
            $this->ctrl = new $ctrlName($this->request);
            $this->method = $method;
        } else {
            throw new HttpInternalError(
                $this->request,
                "Controller view method not found ${ctrl::class}::$view"
            );
        }
    }

    public function respond(): ResponseInterface
    {
        $ctrl = $this->ctrl;
        $view = $this->view;

        return $this->handle($ctrl->$view);
    }
}
