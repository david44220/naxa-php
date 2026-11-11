<?php

declare(strict_types=1);

namespace Naxa\Sdk;

/**
 * One page of a list, the most recent items first.
 *
 *     foreach ($page as $transfer) { ... }          // the items of this page
 *     foreach ($page->all() as $transfer) { ... }   // these, then every following page
 *
 * @implements \IteratorAggregate<int, array<string,mixed>>
 */
final class Page implements \IteratorAggregate, \Countable
{
    /**
     * @param list<array<string,mixed>> $data
     * @param (\Closure(string): Page)|null $after gives the page that follows the item with this identifier
     */
    public function __construct(public readonly array $data, public readonly bool $hasMore, private readonly ?\Closure $after = null)
    {
    }

    /** The page that follows (older items), or null when this one is the last. */
    public function next(): ?self
    {
        $last = $this->data[count($this->data) - 1]['id'] ?? null;
        if (!$this->hasMore || $this->after === null || !is_string($last)) {
            return null;
        }
        return ($this->after)($last);
    }

    /**
     * Every item from this page on, asking Naxa for the following pages as the loop reaches them.
     *
     * @return \Generator<int, array<string,mixed>>
     */
    public function all(): \Generator
    {
        for ($page = $this; $page !== null; $page = $page->next()) {
            yield from $page->data;
        }
    }

    /** @return \ArrayIterator<int, array<string,mixed>> */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->data);
    }

    public function count(): int
    {
        return count($this->data);
    }

    /**
     * @param array<string,mixed> $answer a list as the API answers it
     * @param (\Closure(string): Page)|null $after
     * @internal
     */
    public static function of(array $answer, ?\Closure $after = null): self
    {
        $data = array_values(array_filter((array) ($answer['data'] ?? []), 'is_array'));
        return new self($data, ($answer['has_more'] ?? false) === true, $after);
    }
}
