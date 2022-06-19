<?php $this->layout('readsection'); ?>
<p><?= $text ?></p>
<?php $this->begin('list'); ?>
<ul>
    <li><?= $text ?></li>
</ul>
<?php $this->end(); ?>
