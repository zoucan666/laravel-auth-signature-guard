# laravel-auth-signature-guard

适用于 Laravel Auth 的签名看守器，基于 Laravel Passport


请求必填的 参数

app_id
timestamp
signature
signature_method
signature_nonce

参数签名计算

```php
//排序参数
//按照键名对关联数组进行升序排序
ksort($params);
//编码
$stringToSign = urlencode(http_build_query($params, null, '&', PHP_QUERY_RFC3986));

//签名
$signature = base64_encode(hash_hmac('sha1', $stringToSign, $client->secret, true));
        
其中参数中的时间戳和世界标准时间相差不能超过1分钟。
```


