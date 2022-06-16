<?php

declare(strict_types=1);

namespace Chuck\Util;

use \ValueError;


class ImageSize
{
    public final function __construct(
        public int $origWidth,
        public int $origHeight,
        public int $newWidth,
        public int $newHeight,
        public int $offsetWidth = 0,
        public int $offsetHeight = 0,
    ) {
        if ($newWidth < 0 || $newHeight < 0) {
            throw new ValueError(
                'Image error: width or height must not be smaller than 0 ' .
                    ' (width = ' . (string)$newWidth . ', height = ' . (string)$newHeight . ').'
            );
        }

        // TODO: Arbitrary values. What are sensible values?
        if ($newWidth > 8192 || $newHeight > 8192) {
            throw new ValueError(
                'Image error: width or height must not be larger than 8192px ' .
                    ' (width = ' . (string)$newWidth . ', height = ' . (string)$newHeight . ').'
            );
        }
    }

    public function alreadyInBoundingBox(): bool
    {
        return $this->origWidth <= $this->newWidth &&
            $this->origHeight <= $this->newHeight;
    }

    protected function cropSize(): self
    {
        $scaleWidth = $this->newWidth / $this->origWidth;
        $scaleHeight = $this->newHeight / $this->origHeight;

        if ($this->newWidth === 0 || $this->newHeight === 0) {
            throw new ValueError(
                'Image cropping error: width and height must be larger than 0 ' .
                    ' (width = ' . (string)$this->newWidth . ', height = ' .
                    (string)$this->newHeight . ').'
            );
        }

        if ($scaleWidth === $scaleHeight) {
            // Same aspect ratio as original, nothing needs to be cropped
            $offsetWidth = $offsetHeight = 0;
        } elseif ($scaleWidth > $scaleHeight) {
            // Height needs to be cropped
            $newHeight = $this->origHeight * $scaleWidth;
            $offsetWidth = 0;
            $offsetHeight = ($this->newHeight - $newHeight) / 2;
        } else {
            // Width needs to be cropped
            $newWidth = $this->origWidth * $scaleHeight;
            $offsetWidth = ($this->newWidth - $newWidth) / 2;
            $offsetHeight = 0;
        }

        return new self(
            origWidth: $this->origWidth,
            origHeight: $this->origHeight,
            newWidth: $this->newWidth,
            newHeight: $this->newHeight,
            offsetWidth: (int)floor($offsetWidth),
            offsetHeight: (int)floor($offsetHeight),
        );
    }

    protected function boundingSize(): self
    {
        if ($this->newWidth > 0 && $this->newHeight > 0) {
            // Fit complete image into bounding box without cropping
            //
            // Check which side needs to be scaled by
            // a greater factor and use it to calculate
            // the new size of both sides.

            $scaleWidth = $this->newWidth / $this->origWidth;
            $scaleHeight = $this->newHeight / $this->origHeight;

            if ($scaleWidth < $scaleHeight) {
                $newWidth = $this->origWidth * $scaleWidth;
                $newHeight = $this->origHeight * $scaleWidth;
            } else {
                $newWidth = $this->origWidth * $scaleHeight;
                $newHeight = $this->origHeight * $scaleHeight;
            }
        } elseif ($this->newWidth > 0) {
            // Resize to width, keep aspect ratio
            $newWidth = $this->newWidth;
            $newHeight = (int)floor($this->origHeight * ($this->newWidth / $this->origWidth));
        } elseif ($this->newHeight > 0) {
            // Resize to height, keep aspect ratio
            $newWidth = (int)floor($this->origWidth * ($this->newHeight / $this->origHeight));
            $newHeight = $this->newHeight;
        } else {
            throw new ValueError('Height and/or width must be given');
        }

        return new static(
            origWidth: $this->origWidth,
            origHeight: $this->origHeight,
            newWidth: (int)floor($newWidth),
            newHeight: (int)floor($newHeight),
            offsetWidth: 0,
            offsetHeight: 0,
        );
    }

    public function newSize(bool $crop): self
    {
        if ($crop) {
            return $this->cropSize();
        } else {
            return $this->boundingSize();
        }
    }
}
