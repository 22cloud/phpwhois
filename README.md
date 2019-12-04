# Installation

### Via composer

#### Stable version

`php composer.phar require "dohub/phpwhois":"dev-dev"`

#### Latest development version

`php composer.phar require "dohub/phpwhois":"dev-master"`


# Example usage

(see `example.php`)
```php
// Load composer framework
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require(__DIR__ . '/vendor/autoload.php');
}

use phpwhois;
$name = isset($_GET['name'])?$_GET['name']:'skxx.cn';
$use = new phpwhois\Whois();

if(!$result = $use->lookup($name)){
    print_r($use->getError());
    exit;
}
echo $raw = $use->getRawData();
print_r($result);
```
