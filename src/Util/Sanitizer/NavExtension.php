<?php

declare(strict_types=1);

namespace Chuck\Util\Sanitizer;

use \DOMNode;
use HtmlSanitizer\Extension\ExtensionInterface;
use HtmlSanitizer\Model\Cursor;
use HtmlSanitizer\Node\AbstractTagNode;
use HtmlSanitizer\Node\HasChildrenTrait;
use HtmlSanitizer\Node\NodeInterface;
use HtmlSanitizer\Visitor\AbstractNodeVisitor;
use HtmlSanitizer\Visitor\HasChildrenNodeVisitorTrait;
use HtmlSanitizer\Visitor\NamedNodeVisitorInterface;

class NavNode extends AbstractTagNode
{
    use HasChildrenTrait;

    public function getTagName(): string
    {
        return 'nav';
    }
}


class NavNodeVisitor extends AbstractNodeVisitor implements NamedNodeVisitorInterface
{
    use HasChildrenNodeVisitorTrait;

    protected function getDomNodeName(): string
    {
        return 'nav';
    }

    protected function createNode(DOMNode $domNode, Cursor $cursor): NodeInterface
    {
        return new NavNode($cursor->node);
    }
}

class NavExtension implements ExtensionInterface
{
    public function getName(): string
    {
        return 'nav';
    }

    public function createNodeVisitors(array $config = []): array
    {
        return [
            'nav' => new NavNodeVisitor($config['tags']['nav'] ?? []),
        ];
    }
}
