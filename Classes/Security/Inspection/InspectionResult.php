<?php
namespace Extension14v\T3lockdown\Security\Inspection;

/**
 * Aggregated result of a full request inspection.
 */
final class InspectionResult
{
    private array $matches;

    public function __construct(array $matches = [])
    {
        $this->matches = $matches;
    }

    public function hasMatches(): bool
    {
        return $this->matches !== [];
    }

    public function getMatches(): array
    {
        return $this->matches;
    }

    public function getAttackTypes(): array
    {
        return array_values(array_unique(
            array_map(static fn(AttackMatch $m) => $m->type, $this->matches)
        ));
    }

    public function hasType(string $type): bool
    {
        foreach ($this->matches as $match) {
            if ($match->type === $type) {
                return true;
            }
        }
        return false;
    }

    public function withMatch(AttackMatch $match): self
    {
        $new = clone $this;
        $new->matches[] = $match;
        return $new;
    }
}