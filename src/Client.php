<?php namespace Shucang;

class Client
{
    const kSandboxURL = "http://dev-openapi.365ex.art/api/v1/open";
    const kProductionURL = "https://openapi.365ex.art/api/v1/open";

    /**
     * @var string
     */
    private $appId;

    /**
     * @var OpenSSLAsymmetricKey
     */
    private $appPrivateKey;
    private $todayPublicKey;
    private $isProd = false;

    /**
     * @var string
     */
    private $apiDomain;

    /**
     * @param $appId
     * @param $appPrivateKey
     * @param $todayPublicKey
     * @param $isProd
     * @throws ShucangException
     */
    public function __construct($appId, $appPrivateKey, $todayPublicKey, $isProd = true)
    {
        $this->appId = $appId;

        $this->appPrivateKey = openssl_pkey_get_private($appPrivateKey);
        if ($this->appPrivateKey == false) {
            throw new ShucangException("私钥错误");
        }

        $this->todayPublicKey = openssl_pkey_get_public($todayPublicKey);
        if ($this->todayPublicKey == false) {
            throw new ShucangException("今日公钥错误");
        }

        $this->isProd = $isProd;
        $this->apiDomain = self::kSandboxURL;
        if ($this->isProd) {
            $this->apiDomain = self::kProductionURL;
        }
    }

    public function doRequest($method, $params)
    {
        $body = $this->getRequestBody($method, $params);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->apiDomain);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
        //设置cURL允许执行的最长秒数
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('content-type: application/json;charset=utf-8'));
        if (!empty($options)) {
            curl_setopt_array($ch, $options);
        }
        //https请求 不验证证书和host
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    /**
     * 获取请求body值
     *
     * @param $method
     * @param $params
     * @return array
     * @throws ShucangException
     */
    private function getRequestBody($method, $params)
    {
        $request = [
            "app_id" => $this->appId,
            "timestamp" => (string)time(),
            "nonce" => $this->nonce(),
            "method" => $method
        ];

        if (openssl_public_encrypt(json_encode($params), $encrypted, $this->todayPublicKey) === false) {
            throw new ShucangException("加密data数据失败");
        }

        $request["data"] = base64_encode($encrypted);

        $request["sign"] = $this->generateSign($request);

        return $request;
    }

    private function generateSign($data)
    {
        $str = $this->getSignContent($data);

        if (openssl_sign($str, $sign, $this->appPrivateKey, OPENSSL_ALGO_SHA256) === false) {
            throw new ShucangException("生成签名失败");
        }

        return base64_encode($sign);
    }

    private function getSignContent($data)
    {
        ksort($data);
        $strs = [];
        foreach ($data as $k => $v) {
            $strs[] = "$k" . "=" . "$v";
        }

        return implode("&", $strs);
    }

    private function nonce()
    {
        return md5(uniqid(mt_rand(), true));
    }

}