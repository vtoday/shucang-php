<?php namespace Vtoday\Shucang\Exceptions;


class ApiException extends Exception
{
    /**
     * @var string
     */
    protected $errCode;

    /**
     * @var string
     */
    protected $errMessage;

    /**
     * @param string $errCode
     * @param string $errMessage
     */
    public function __construct($errCode, $errMessage)
    {
        $this->errCode = $errCode;
        $this->errMessage = $errMessage;
    }

    /**
     * @return string
     */
    public function getErrCode()
    {
        return $this->errCode;
    }

    /**
     * @return string
     */
    public function getErrMessage()
    {
        return $this->errMessage;
    }

}
