<?php namespace Vtoday\Shucang;

use Vtoday\Shucang\Exceptions\ApiException;
use Vtoday\Shucang\Exceptions\ConfigurationException;
use Vtoday\Shucang\Exceptions\RuntimeException;

class Client
{
    const API_SANDBOX_URL = "http://dev-openapi.365ex.art/api/v1/open";
    const API_PRODUCTION_URL = "https://openapi.365ex.art/api/v1/open";

    const SUCCESS_CODE = "200";

    const KEY_TYPE_PUBLIC = 1;
    const KEY_TYPE_PRIVATE = 2;

    /**
     * 应用私钥
     *
     * @var string
     */
    private $appId;

    /**
     * 应用私钥
     *
     * @var \OpenSSLAsymmetricKey|resource
     */
    private $appPrivateKey;

    /**
     * 今日公钥
     *
     * @var \OpenSSLAsymmetricKey|resource
     */
    private $todayPublicKey;

    /**
     * 是否生产环境
     *
     * @var bool
     */
    private $isProd = false;

    /**
     * 请求接口地址
     *
     * @var string
     */
    private $apiDomain;

    /**
     * @param $appId
     * @param $appPrivateKey
     * @param $todayPublicKey
     * @param $isProd
     *
     * @throws ConfigurationException
     */
    public function __construct($appId, $appPrivateKey, $todayPublicKey, $isProd = true)
    {
        //应用ID
        $this->appId = $appId;

        //应用私钥
        $this->appPrivateKey = openssl_pkey_get_private($this->convertRsaKey($appPrivateKey, self::KEY_TYPE_PRIVATE));
        if ($this->appPrivateKey == false) {
            throw new ConfigurationException("私钥错误");
        }

        //今日公钥
        $this->todayPublicKey = openssl_pkey_get_public($this->convertRsaKey($todayPublicKey, self::KEY_TYPE_PUBLIC));
        if ($this->todayPublicKey == false) {
            throw new ConfigurationException("今日公钥错误");
        }

        $this->isProd = $isProd;
        $this->apiDomain = self::API_SANDBOX_URL;
        if ($this->isProd) {
            $this->apiDomain = self::API_PRODUCTION_URL;
        }
    }

    /**
     * 执行请求
     *
     * @param $method
     * @param $params
     *
     * @return array|string
     * @throws ApiException
     * @throws RuntimeException
     */
    public function doRequest($method, $params)
    {
        $body = $this->getRequestBody($method, $params);
        $content = $this->doCurl($body);

        $data = json_decode($content, true);
        if (empty($data)) {
            throw new ApiException("接口返回数据格式错误");
        }

        $code = isset($data["code"]) ? $data["code"] : "";
        $message = isset($data["message"]) ? $data["message"] : "";
        if ($code == "") {
            throw new ApiException("接口没有返回code码");
        }

        if ($code != self::SUCCESS_CODE) {
            throw new ApiException(sprintf("接口错误：code: %s, message: %s ", $code, $message));
        }

        $sign = isset($data["sign"]) ? $data["sign"] : "";
        if ($sign == "") {
            throw new ApiException("接口返回数据没有签名");
        }

        if (!$this->verifySign($data)) {
            throw new ApiException("接口返回值验证签名错误");
        }

        $bizData = isset($data["data"]) ? $data["data"] : "";
        if ($bizData == "") {
            return [];
        }

        return $this->decryptData($bizData);
    }

    /**
     * curl接口请求
     *
     * @param string $body
     *
     * @return bool|string
     */
    private function doCurl($body)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->apiDomain);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
        //设置cURL允许执行的最长秒数
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['content-type: application/json;charset=utf-8']);
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
     *
     * @return array
     * @throws RuntimeException
     */
    private function getRequestBody($method, $params)
    {
        $request = [
            "app_id"    => $this->appId,
            "timestamp" => (string)time(),
            "nonce"     => $this->nonce(),
            "method"    => $method,
        ];

        $request["data"] = $this->encryptData($params);

        $request["sign"] = $this->generateSign($request);

        return $request;
    }

    /**
     * 加密数据
     *
     * @param $data
     *
     * @return string
     * @throws RuntimeException
     */
    public function encryptData($data)
    {
        if (openssl_public_encrypt(json_encode($data), $encrypted, $this->todayPublicKey) === false) {
            throw new RuntimeException("加密data数据失败");
        }

        return base64_encode($encrypted);
    }

    /**
     * 解密数据
     *
     * @param $data
     *
     * @return string
     * @throws RuntimeException
     */
    public function decryptData($data)
    {
        if (openssl_private_decrypt(base64_decode($data), $encrypted, $this->appPrivateKey) === false) {
            throw new RuntimeException("解密data数据失败");
        }

        return json_decode($encrypted, true);
    }

    /**
     * 生成签名字符
     *
     * @param $data
     *
     * @return string
     * @throws RuntimeException
     */
    public function generateSign($data)
    {
        $str = $this->getSignContent($data);

        if (openssl_sign($str, $sign, $this->appPrivateKey, OPENSSL_ALGO_SHA256) === false) {
            throw new RuntimeException("生成签名失败");
        }

        return base64_encode($sign);
    }

    /**
     * 验签
     *
     * @param $data
     *
     * @return bool
     */
    public function verifySign($data)
    {
        $sign = $data["sign"];
        $str = $this->getSignContent($data);

        return openssl_verify($str, base64_decode($sign), $this->todayPublicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * 生成待签名字符串
     *
     * @param array $data
     *
     * @return string
     */
    private function getSignContent($data)
    {
        ksort($data);
        $strs = [];
        foreach ($data as $k => $v) {
            if ($k == "sign") {
                continue;
            }
            $strs[] = "$k" . "=" . "$v";
        }

        return implode("&", $strs);
    }

    /**
     * 生产随机字符串
     *
     * @return string
     */
    private function nonce()
    {
        return md5(uniqid(mt_rand(), true));
    }


    /**
     * Convert one line key to standard format
     *
     * @param string $key
     * @param int    $type
     *
     * @return string
     */
    public function convertRsaKey($key, $type)
    {
        $lines = [];

        if ($type == self::KEY_TYPE_PUBLIC) {
            $lines[] = '-----BEGIN PUBLIC KEY-----';
        } else {
            $lines[] = '-----BEGIN RSA PRIVATE KEY-----';
        }

        for ($i = 0; $i < strlen($key); $i += 64) {
            $lines[] = trim(substr($key, $i, 64));
        }

        if ($type == self::KEY_TYPE_PUBLIC) {
            $lines[] = '-----END PUBLIC KEY-----';
        } else {
            $lines[] = '-----END RSA PRIVATE KEY-----';
        }

        return implode("\n", $lines);
    }

}
