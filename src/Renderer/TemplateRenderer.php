<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\RequestInterface;
use Chuck\TemplateInterface;


class TemplateRenderer extends Renderer
{
    protected array $context;
    protected string $template;

    public function __construct(
        protected RequestInterface $request,
        protected mixed $data,
        protected array $args,
    ) {
        parent::__construct($request, $data, $args);

        $context = $this->data ?? [];
        $this->template = implode('::', explode(':', $this->args[0]));

        if ($context instanceof \Traversable) {
            $this->context = iterator_to_array($context);
        } else {
            $this->context = $context;
        }
    }

    public function render(): string
    {
        $class = $this->request->getConfig()->registry(TemplateInterface::class);
        $template = new $class($this->request);
        return $template->render($this->template, $this->context);
    }

    public function headers(): iterable
    {
        if (array_key_exists('contentType', $this->args)) {
            return [
                [
                    'name' => 'Content-Type',
                    'value' => $this->args['contentType'],
                    'replace' => true,
                ],
            ];
        }

        return [
            [
                'name' => 'Content-Type',
                'value' => 'text/html',
                'replace' => true,
            ],
        ];
    }
}
