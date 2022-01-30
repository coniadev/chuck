<?php

declare(strict_types=1);

namespace Chuck\Util;

class Html
{
    public function __construct(RequestInterface $request = null)
    {
        $this->request = $request;
    }

    public function clean(string $html, ?array $extensions = []): string
    {
        $builder = \HtmlSanitizer\SanitizerBuilder::createDefault();
        $builder->registerExtension(new Sanitizer\BlockExtension());
        $builder->registerExtension(new Sanitizer\HeadFootExtension());
        $builder->registerExtension(new Sanitizer\NavExtension());

        if (count($extensions) == 0) {
            $config = $this->request->config->get('sanitizer');
        } else {
            $config = ['extensions' => $extensions];
        }
        $sanitizer = $builder->build($config);

        // also remove empty lines
        return preg_replace(
            "/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/",
            PHP_EOL,
            $sanitizer->sanitize($html)
        );
    }
}
