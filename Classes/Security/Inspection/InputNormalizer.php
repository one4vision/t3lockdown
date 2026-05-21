<?php

declare(strict_types=1);

namespace Extension14v\T3lockdown\Security\Inspection;

/**
 * Normalizes potentially obfuscated input values before security inspection.
 */
final readonly class InputNormalizer
{
    public function normalize(string $value): string
    {
        $normalized = trim($value);
        for ($i = 0; $i < 3; $i++) {
            $decoded = rawurldecode($normalized);
            if ($decoded === $normalized) {
                break;
            }
            $normalized = $decoded;
        }
        $normalized = html_entity_decode($normalized, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $normalized = preg_replace('/\/\*.*?\*\//s', '', $normalized) ?? $normalized;
        $normalized = str_replace(["\0", "\r", "\n", "\t"], ' ', $normalized);
        $normalized = preg_replace('/\s+/u', ' ', $normalized) ?? $normalized;
        return trim($normalized);
    }

    /**
     * @param array<string|int, mixed> $payload
     * @return array<string|int, mixed>
     */
    public function normalizeArray(array $payload): array
    {
        foreach ($payload as $key => $value) {
            if (is_array($value)) {
                $payload[$key] = $this->normalizeArray($value);
                continue;
            }
            if (is_string($value)) {
                $payload[$key] = $this->normalize($value);
            }
        }
        return $payload;
    }

    /**
     * @param array<string, array<int, string>> $headers
     * @return array<string, array<int, string>>
     */
    public function normalizeHeaders(array $headers): array
    {
        foreach ($headers as $name => $values) {
            foreach ($values as $index => $value) {
                $headers[$name][$index] = $this->normalize($value);
            }
        }
        return $headers;
    }
}