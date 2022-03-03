<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;
use Chuck\Body\Text;
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

        if ($this->data instanceof \Traversable) {
            $this->context = iterator_to_array($this->data);
        } else {
            $this->context = $this->data ?? [];
        }

        $this->template = $this->args[0];
    }

    public function render(): string
    {
        $request = $this->request;
        $config = $request->getConfig();
        $class = $request->getRegistry()->get(TemplateInterface::class);
        $template = new $class(
            $this->request,
            defaults: [
                'config' => $config,
                'request' => $request,
                'router' => $request->getRouter(),
                'debug' => $config->debug(),
                'env' => $config->env(),
            ]
        );
        return $template->render($this->template, $this->context);
    }

    public function body(): Body
    {
        return new Text($this->render());
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
