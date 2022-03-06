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

class AsideNode extends AbstractTagNode
{
    use HasChildrenTrait;

    public function getTagName(): string
    {
        return 'aside';
    }
}


class AsideNodeVisitor extends AbstractNodeVisitor implements NamedNodeVisitorInterface
{
    use HasChildrenNodeVisitorTrait;

    protected function getDomNodeName(): string
    {
        return 'aside';
    }

    protected function createNode(DOMNode $domNode, Cursor $cursor): NodeInterface
    {
        return new AsideNode($cursor->node);
    }
}

class ArticleNode extends AbstractTagNode
{
    use HasChildrenTrait;

    public function getTagName(): string
    {
        return 'article';
    }
}


class ArticleNodeVisitor extends AbstractNodeVisitor implements NamedNodeVisitorInterface
{
    use HasChildrenNodeVisitorTrait;

    protected function getDomNodeName(): string
    {
        return 'article';
    }

    protected function createNode(DOMNode $domNode, Cursor $cursor): NodeInterface
    {
        return new ArticleNode($cursor->node);
    }
}

class SectionNode extends AbstractTagNode
{
    use HasChildrenTrait;

    public function getTagName(): string
    {
        return 'section';
    }
}


class SectionNodeVisitor extends AbstractNodeVisitor implements NamedNodeVisitorInterface
{
    use HasChildrenNodeVisitorTrait;

    protected function getDomNodeName(): string
    {
        return 'section';
    }

    protected function createNode(DOMNode $domNode, Cursor $cursor): NodeInterface
    {
        return new SectionNode($cursor->node);
    }
}

class BlockExtension implements ExtensionInterface
{
    public function getName(): string
    {
        return 'block';
    }

    public function createNodeVisitors(array $config = []): array
    {
        return [
            'aside' => new AsideNodeVisitor($config['tags']['aside'] ?? []),
            'article' => new ArticleNodeVisitor($config['tags']['article'] ?? []),
            'section' => new SectionNodeVisitor($config['tags']['section'] ?? []),
        ];
    }
}
