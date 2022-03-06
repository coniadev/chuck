<?php $this->layout('readsection'); ?>
<p><?= $this->text ?></p>
<?php $this->begin('list'); ?>
<ul>
    <li><?= $this->text ?></li>
</ul>
<?php $this->end(); ?>
