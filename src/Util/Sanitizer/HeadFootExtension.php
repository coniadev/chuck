<?php

declare(strict_types=1);

namespace Chuck\Util\Sanitizer;

use HtmlSanitizer\Extension\ExtensionInterface;
use HtmlSanitizer\Model\Cursor;
use HtmlSanitizer\Node\AbstractTagNode;
use HtmlSanitizer\Node\HasChildrenTrait;
use HtmlSanitizer\Node\NodeInterface;
use HtmlSanitizer\Visitor\AbstractNodeVisitor;
use HtmlSanitizer\Visitor\HasChildrenNodeVisitorTrait;
use HtmlSanitizer\Visitor\NamedNodeVisitorInterface;

class HeaderNode extends AbstractTagNode
{
    use HasChildrenTrait;

    public function getTagName(): string
    {
        return 'header';
    }
}


class HeaderNodeVisitor extends AbstractNodeVisitor implements NamedNodeVisitorInterface
{
    use HasChildrenNodeVisitorTrait;

    protected function getDomNodeName(): string
    {
        return 'header';
    }

    protected function createNode(\DOMNode $domNode, Cursor $cursor): NodeInterface
    {
        return new HeaderNode($cursor->node);
    }
}

class FooterNode extends AbstractTagNode
{
    use HasChildrenTrait;

    public function getTagName(): string
    {
        return 'footer';
    }
}


class FooterNodeVisitor extends AbstractNodeVisitor implements NamedNodeVisitorInterface
{
    use HasChildrenNodeVisitorTrait;

    protected function getDomNodeName(): string
    {
        return 'footer';
    }

    protected function createNode(\DOMNode $domNode, Cursor $cursor): NodeInterface
    {
        return new FooterNode($cursor->node);
    }
}

class HeadFootExtension implements ExtensionInterface
{
    public function getName(): string
    {
        return 'headfoot';
    }

    public function createNodeVisitors(array $config = []): array
    {
        return [
            'header' => new HeaderNodeVisitor($config['tags']['header'] ?? []),
            'footer' => new FooterNodeVisitor($config['tags']['footer'] ?? []),
        ];
    }
}
