Templates
=========


    use Chuck\{App, Config, Router, Route, Request, ResponseFactory};
    use Chuck\Renderer\TemplateRenderer;

    $config = new Config('chuck');

    // Add template support
    $config->addRenderer('template', TemplateRenderer::class, '/path/to/templates');
    use Chuck\Renderer\TemplateRenderer;