<?php
namespace Extension14v\T3lockdown\Security\Inspection;

/**
 * Represents a single pattern match found during request inspection.
 */
final readonly class AttackMatch
{
    public function __construct(
        public readonly string $type,
        public readonly string $ruleName,
        public readonly string $fieldName,
        public readonly string $fieldValue,
        public readonly bool $fromHeader = false,
    ) {
    }
}