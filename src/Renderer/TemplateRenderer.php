<?php

declare(strict_types=1);

namespace Chuck\Renderer;

use Chuck\Body\Body;
use Chuck\Body\Text;
use Chuck\RequestInterface;
use Chuck\Template\Engine;


class TemplateRenderer extends Renderer
{
    protected array $context;
    protected string $template;

    public function __construct(
        RequestInterface $request,
        mixed $data,
        array $args,
        mixed $settings,
    ) {
        parent::__construct($request, $data, $args, $settings);

        if ($this->data instanceof \Traversable) {
            $this->context = iterator_to_array($this->data);
        } else {
            $this->context = $this->data ?? [];
        }

        $this->template = $this->args[0];
    }

    public function render(): Body
    {
        $request = $this->request;
        $config = $request->config();
        $template = new Engine(
            $this->settings,
            defaults: [
                'config' => $config,
                'request' => $request,
                'router' => $request->router(),
                'debug' => $config->debug(),
                'env' => $config->env(),
            ]
        );
        return new Text($template->render($this->template, $this->context));
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
