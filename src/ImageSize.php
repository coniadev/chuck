<?php

declare(strict_types=1);

namespace Chuck;


class ImageSize
{
    public function __construct(
        public int $origWidth,
        public int $origHeight,
        public int $newWidth,
        public int $newHeight,
        public ?int $offsetWidth = 0,
        public ?int $offsetHeight = 0,
    ) {
    }

    public function alreadyInBoundingBox(): bool
    {
        return $this->origWidth <= $this->newWidth &&
            $this->origHeight <= $this->newHeight;
    }

    protected function cropSize(): self
    {
        $offsetWidth = 0;
        $offsetHeight = 0;

        if ($this->newWidth > 0 && $this->newHeight > 0) {
            $scaleWidth = $this->newWidth / $this->origWidth;
            $scaleHeight = $this->newHeight / $this->origHeight;

            if ($scaleWidth < $scaleHeight) {
                $newWidth = $this->origWidth * $scaleWidth;
                $newHeight = $this->origHeight * $scaleWidth;
            } else {
                $newWidth = $this->origWidth * $scaleHeight;
                $newHeight = $this->origHeight * $scaleHeight;
            }
        } elseif ($this->newWeight > 0) {
            $newWidth = $this->newWidth;
            $newHeight = $this->origHeight * ($this->newWidth / $this->origWidth);
        } elseif ($this->newHeight > 0) {
            $newWidth = $this->origWidth * ($this->newHeight / $this->origHeight);
            $newHeight = $this->newHeight;
        } else {
            throw new \InvalidArgumentException('Height and/or width must be given');
        }

        return new self(
            origWidth: $this->origWidth,
            origHeight: $this->origHeight,
            newWidth: (int)floor($newWidth),
            newHeight: (int)floor($newHeight),
            offsetWidth: $offsetWidth,
            offsetHeight: $offsetHeight,
        );
    }

    protected function boundingSize(): self
    {
        if ($this->newWidth > 0 && $this->newHeight > 0) {
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
            $newWidth = $this->newWidth;
            $newHeight = (int)floor($this->origHeight * ($this->newWidth / $this->origWidth));
        } elseif ($this->newHeight > 0) {
            $newWidth = (int)floor($this->origWidth * ($this->newHeight / $this->origHeight));
            $newHeight = $this->newHeight;
        } else {
            throw new \InvalidArgumentException('Height and/or width must be given');
        }

        return new self(
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
