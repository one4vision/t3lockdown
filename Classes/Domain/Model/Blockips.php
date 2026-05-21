<?php
namespace Extension14v\T3lockdown\Domain\Model;

use TYPO3\CMS\Extbase\DomainObject\AbstractEntity;

class Blockips extends AbstractEntity
{
    /**
     * @var \DateTime|null The date of the attack. Can be null if no attack date is specified.
     */
    protected ?\DateTime $attackDate = null;

    /**
     * @var string The blocked remote IP address.
     */
    protected string $remoteIp = '';

    protected float $blockMinutes = 0.000;
    protected int $fromAttempt = 0;

    /**
     * Get the date of the attack.
     *
     * @return \DateTime|null The attack date, or null if no attack date is specified.
     */
    public function getAttackDate(): ?\DateTime {
        return $this->attackDate;
    }

    /**
     * Set the date of the attack.
     *
     * @param \DateTime $attackDate The date to set.
     */
    public function setAttackDate(\DateTime $attackDate): void {
        $this->attackDate = $attackDate;
    }

    /**
     * Get the blocked remote IP address.
     *
     * @return string The blocked remote IP address.
     */
    public function getRemoteIp(): string {
        return $this->remoteIp;
    }

    /**
     * Set the blocked remote IP address.
     *
     * @param string $remoteIp The IP address to block.
     */
    public function setRemoteIp(string $remoteIp): void {
        $this->remoteIp = $remoteIp;
    }

    public function getBlockMinutes(): float
    {
        return $this->blockMinutes;
    }

    public function setBlockMinutes(float $blockMinutes): void
    {
        $this->blockMinutes = $blockMinutes;
    }

    public function getFromAttempt(): int
    {
        return $this->fromAttempt;
    }

    public function setFromAttempt(int $fromAttempt): void
    {
        $this->fromAttempt = $fromAttempt;
    }


}