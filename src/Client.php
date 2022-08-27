<?php namespace Vtoday\Shucang;

use Vtoday\Shucang\Exceptions\ApiException;
use Vtoday\Shucang\Exceptions\ConfigurationException;
use Vtoday\Shucang\Exceptions\InvalidParamException;
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
     * @throws InvalidParamException
     */
    public function doRequest($method, $params)
    {
        $body = $this->getRequestBody($method, $params);
        $content = $this->doCurl($body);

        $data = json_decode($content, true);
        if (empty($data)) {
            throw new InvalidParamException("接口返回数据格式错误");
        }

        $code = isset($data["code"]) ? $data["code"] : "";
        $message = isset($data["message"]) ? $data["message"] : "";
        if ($code == "") {
            throw new InvalidParamException("接口没有返回code码");
        }

        if ($code != self::SUCCESS_CODE) {
            throw new InvalidParamException(sprintf("接口错误：code: %s, message: %s ", $code, $message));
        }

        $sign = isset($data["sign"]) ? $data["sign"] : "";
        if ($sign == "") {
            throw new InvalidParamException("接口返回数据没有签名");
        }

        if (!$this->verifySign($data)) {
            throw new InvalidParamException("接口返回值验证签名错误");
        }

        $bizData = isset($data["data"]) ? $data["data"] : "";
        if ($bizData == "") {
            return [];
        }

        return $this->decryptData($bizData);
    }

    /**
     * 获取接口请求数据
     *
     * @return array
     * @throws ApiException
     * @throws RuntimeException
     */
    public function parseRequestData()
    {
        $body = file_get_contents('php://input');

        $params = $this->checkRequestBody($body);

        if (!$this->verifySign($params)) {
            throw new ApiException("3002", "签名校验失败");
        }

        $method = $params["method"];

        $data = [];
        if (!empty($params["data"])) {
            $data = $this->decryptData($params["data"]);
        }

        return [$method, $data];
    }

    /**
     * 生成签名返回结果
     *
     * @param $code
     * @param $message
     * @param $data
     *
     * @return array
     * @throws RuntimeException
     */
    public function genSignResponse($code, $message, $data)
    {
        $response = [
            "code"      => (string)$code,
            "message"   => (string)$message,
            "app_id"    => $this->appId,
            "timestamp" => (string)time(),
            "nonce"     => $this->nonce(),
            "data"      => "",
        ];

        if (!empty($data)) {
            $response["data"] = $this->encryptData($data);
        }

        $response["sign"] = $this->generateSign($data);

        return $response;
    }

    /**
     * 校验请求参数
     *
     * @param $body
     *
     * @return array
     *
     * @throws ApiException
     */
    private function checkRequestBody($body)
    {
        if (empty($body)) {
            throw new ApiException("4000", "请求参数为空");
        }

        $params = json_decode($body, true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new ApiException("4000", "请求参数非json格式");
        }

        if (empty($params)) {
            throw new ApiException("4000", "请求参数解析为空");
        }

        if (empty($params["app_id"])) {
            throw new ApiException("4001", "缺少参数app_id");
        }

        if ($params["app_id"] != $this->appId) {
            throw new ApiException("4001", "app_id错误");
        }

        if (empty($params["sign"])) {
            throw new ApiException("4002", "缺少参数sign");
        }

        if (empty($params["nonce"])) {
            throw new ApiException("4003", "缺少参数nonce");
        }

        if (empty($params["timestamp"])) {
            throw new ApiException("4007", "缺少参数timestamp");
        }

        if (empty($params["method"])) {
            throw new ApiException("4006", "缺少参数method");
        }

        if (empty($params["data"])) {
            throw new ApiException("4004", "缺少业务参数data");
        }

        if (time() - int($params["timestamp"]) > 600) {
            throw new ApiException("4008", "请求已过期");
        }

        return $params;
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
