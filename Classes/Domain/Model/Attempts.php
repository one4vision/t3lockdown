<?php
namespace Extension14v\T3lockdown\Domain\Model;

use TYPO3\CMS\Extbase\DomainObject\AbstractEntity;

class Attempts extends AbstractEntity
{
    /**
     * @var ?\DateTime The date of the attack attempt
     */
    protected ?\DateTime $attackDate = null;

    /**
     * @var string The host of the TYPO3 installation
     */
    protected string $t3host = '';

    /**
     * @var string The request file
     */
    protected string $requestFile = '';

    /**
     * @var string The request method
     */
    protected string $requestMethod = '';

    /**
     * @var string The input variables
     */
    protected string $inputVars = '';

    /**
     * @var string The remote IP address
     */
    protected string $remoteIp = '';

    /**
     * @var string The user agent string
     */
    protected string $useragent = '';

    /**
     * @var string The details of the attack attempt
     */
    protected string $details = '';

    protected string $requestUrl = '';
    protected int $fromHeader = 0;
    protected string $attackTypes = '';
    protected string $encodedDetails = '';
    /**
     * Get the attack date.
     *
     * @return ?\DateTime The attack date
     */
    public function getAttackDate(): ?\DateTime {
        return $this->attackDate;
    }

    /**
     * Set the attack date.
     *
     * @param \DateTime $attackDate The attack date
     */
    public function setAttackDate(\DateTime $attackDate): void {
        $this->attackDate = $attackDate;
    }

    /**
     * Get the TYPO3 host.
     *
     * @return string The TYPO3 host
     */
    public function getT3host(): string {
        return $this->t3host;
    }

    /**
     * Set the TYPO3 host.
     *
     * @param string $t3host The TYPO3 host
     */
    public function setT3host(string $t3host): void {
        $this->t3host = $t3host;
    }

    /**
     * Get the request file.
     *
     * @return string The request file
     */
    public function getRequestFile(): string {
        return $this->requestFile;
    }

    /**
     * Set the request file.
     *
     * @param string $requestFile The request file
     */
    public function setRequestFile(string $requestFile): void {
        $this->requestFile = $requestFile;
    }

    /**
     * Get the request method.
     *
     * @return string The request method
     */
    public function getRequestMethod(): string {
        return $this->requestMethod;
    }

    /**
     * Set the request method.
     *
     * @param string $requestMethod The request method
     */
    public function setRequestMethod(string $requestMethod): void {
        $this->requestMethod = $requestMethod;
    }

    /**
     * Get the input variables.
     *
     * @return string The input variables
     */
    public function getInputVars(): string {
        return $this->inputVars;
    }

    /**
     * Set the input variables.
     *
     * @param string $inputVars The input variables
     */
    public function setInputVars(string $inputVars): void {
        $this->inputVars = $inputVars;
    }

    /**
     * Get the remote IP address.
     *
     * @return string The remote IP address
     */
    public function getRemoteIp(): string {
        return $this->remoteIp;
    }

    /**
     * Set the remote IP address.
     *
     * @param string $remoteIp The remote IP address
     */
    public function setRemoteIp(string $remoteIp): void {
        $this->remoteIp = $remoteIp;
    }

    /**
     * Get the user agent string.
     *
     * @return string The user agent string
     */
    public function getUseragent(): string {
        return $this->useragent;
    }

    /**
     * Set the user agent string.
     *
     * @param string $useragent The user agent string
     */
    public function setUseragent(string $useragent): void {
        $this->useragent = $useragent;
    }

    /**
     * Get the details of the attack attempt.
     *
     * @return string The details of the attack attempt
     */
    public function getDetails(): string {
        return $this->details;
    }

    /**
     * Set the details of the attack attempt.
     *
     * @param string $details The details of the attack attempt
     */
    public function setDetails(string $details): void {
        $this->details = $details;
    }

    public function getRequestUrl(): string
    {
        return $this->requestUrl;
    }

    public function setRequestUrl(string $requestUrl): void
    {
        $this->requestUrl = $requestUrl;
    }

    public function getFromHeader(): int
    {
        return $this->fromHeader;
    }

    public function setFromHeader(int $fromHeader): void
    {
        $this->fromHeader = $fromHeader;
    }

    public function getAttackTypes(): string
    {
        return $this->attackTypes;
    }

    public function setAttackTypes(string $attackTypes): void
    {
        $this->attackTypes = $attackTypes;
    }

    public function getEncodedDetails(): string
    {
        return $this->encodedDetails;
    }

    public function setEncodedDetails(string $encodedDetails): void
    {
        $this->encodedDetails = $encodedDetails;
    }


}