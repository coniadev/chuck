File Uploads
============


Request helper:

```php
if ($request->hasFile('fieldname')) {
    $file = $request->file('fieldname');

    if ($file->isValid()) {
        $file->move('/new/path');
    }
}
```

Uploaded via HTML array, like `<input type="file" name="fieldname[]"/>`:


```php
if ($request->hasFile('fieldname') && $request->hasMultipleFiles('fieldname')) {
    $files = $request->files('fieldname');

    foreach ($files as $file) {
        if ($file->isValid()) {
            $file->move('/new/path/' . $file->name);
        }
    }
}
```
