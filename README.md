# 今日数字藏品交易服务平台--PHP版SDK

### 安装

```shell
composer require vtoday/shucang
```

### 客户端初始化

```php

include "./vendor/autoload.php";

$appId = "1002";
$privateKey = "MIIEvAIBADANBgkq......jkl9aD/5k8I/Hag==";
$publicKey = "MIIBIjANBgkq......IDAQAB";


try {
    $client = new \Vtoday\Shucang\Client($appId, $privateKey, $publicKey, false);

} catch (\Vtoday\Shucang\Exceptions\ConfigurationException $e) {
    //do something ...

}

```

### 调用`同步藏品信息`接口

```php
try {
    $client->doRequest("collection.info.sync", [
        "product_id"   => "123",
        "product_name" => "cccccccccccc",
        //other fields......
        //注意字段值类型，需要严格匹配类型值
    ]);
} catch (\Vtoday\Shucang\Exceptions\InvalidParamException $e) {
    // do something ...

}
```

### 提供`查询用户信息`接口

```php
try {
    $method = "";
    [$method, $data] = $client->parseRequestData();
 
     $bizData = [];
    // do something ......

    $response = $client->genSignResponse(\Vtoday\Shucang\Client::SUCCESS_CODE, "成功", $method, $bizData);
    
} catch (\Vtoday\Shucang\Exceptions\ApiException $exception) {
    $response = $client->genSignResponse($exception->getErrCode(), $exception->getErrMessage(), $method);
    // do something ......
}catch(\Exception $exception){
    $response = $client->genSignResponse("5500", $exception->getMessage(), $method);
    // do something ......
}

//return $response
```
