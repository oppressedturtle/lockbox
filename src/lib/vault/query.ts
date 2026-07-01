/**
 * Client-side vault organisation: folders, tags, search, and sort (Phase 3 item 2).
 *
 * Everything here runs **entirely in the browser over already-decrypted items**.
 * The server stores only opaque ciphertext (CRYPTO.md §4.1) and can neither
 * search nor sort — so folders/tags/search must be computed locally from the
 * plaintext {@link VaultItem}s after they are decrypted.
 *
 * A {@link VaultEntry} pairs a decrypted item with the server-side metadata
 * (id, version, updatedAt) that isn't part of the encrypted plaintext, so the
 * list can be sorted by recency and keyed by id without re-deriving anything.
 */
import type { VaultItem, VaultItemKind } from './schema';

/** A decrypted item together with the server metadata that lives outside the blob. */
export interface VaultEntry {
  /** Client-generated UUID, also bound into the item's GCM AAD. */
  id: string;
  /** The decrypted, validated plaintext. */
  item: VaultItem;
  /** Optimistic-concurrency version from the server row. */
  version: number;
  /** When the server row was last written. */
  updatedAt: Date;
}

/** A folder name paired with how many entries live in it. */
export interface FolderSummary {
  name: string;
  count: number;
}

/** A tag paired with how many entries carry it. */
export interface TagSummary {
  tag: string;
  count: number;
}

/**
 * Fields we index for text search. Deliberately excludes raw secrets
 * (password, CVV, TOTP seed, full card number): searching is a convenience over
 * the *labels* of an entry, and keeping secrets out of the haystack avoids
 * matching a query fragment against a password by accident. All of this is
 * in-memory on the client, but mirroring typical password-manager behaviour
 * keeps the UX predictable.
 */
function searchableText(item: VaultItem): string {
  const parts: string[] = [item.title];
  if (item.folder) parts.push(item.folder);
  if (item.tags) parts.push(...item.tags);
  if (item.notes) parts.push(item.notes);

  switch (item.kind) {
    case 'login':
      if (item.username) parts.push(item.username);
      if (item.url) parts.push(item.url);
      break;
    case 'note':
      if (item.body) parts.push(item.body);
      break;
    case 'card':
      if (item.cardholderName) parts.push(item.cardholderName);
      if (item.brand) parts.push(item.brand);
      // Only the last 4 digits are searchable — never the full PAN.
      if (item.number) {
        const digits = item.number.replace(/\D/g, '');
        if (digits.length >= 4) parts.push(digits.slice(-4));
      }
      break;
  }

  return parts.join('\n').toLowerCase();
}

/**
 * Collect the distinct folders across `entries` with entry counts, sorted
 * alphabetically (case-insensitive). Entries without a folder are omitted.
 * Folder names are compared verbatim (after trimming empties) — nesting via a
 * separator like `/` is a display concern, not modelled here.
 */
export function collectFolders(entries: readonly VaultEntry[]): FolderSummary[] {
  const counts = new Map<string, number>();
  for (const { item } of entries) {
    const folder = item.folder?.trim();
    if (!folder) continue;
    counts.set(folder, (counts.get(folder) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
}

/**
 * Collect the distinct tags across `entries` with counts. Sorted by count
 * (descending) then alphabetically, so the most-used tags surface first.
 * Tags are trimmed; blanks are ignored. A tag is counted once per entry even if
 * it appears twice on that entry.
 */
export function collectTags(entries: readonly VaultEntry[]): TagSummary[] {
  const counts = new Map<string, number>();
  for (const { item } of entries) {
    if (!item.tags) continue;
    const seen = new Set<string>();
    for (const raw of item.tags) {
      const tag = raw.trim();
      if (!tag || seen.has(tag)) continue;
      seen.add(tag);
      counts.set(tag, (counts.get(tag) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort(
      (a, b) => b.count - a.count || a.tag.localeCompare(b.tag, undefined, { sensitivity: 'base' }),
    );
}

/** Predicate filters applied to the vault list. All provided filters must match (AND). */
export interface VaultFilter {
  /** Free-text query matched (case-insensitively) against searchable fields. */
  query?: string;
  /** Restrict to a single folder (exact, trimmed match). */
  folder?: string;
  /** Restrict to entries carrying *all* of these tags. */
  tags?: readonly string[];
  /** Restrict to a single item kind. */
  kind?: VaultItemKind;
}

function matchesQuery(item: VaultItem, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const haystack = searchableText(item);
  // Every whitespace-separated term must appear (AND) — cheap fuzzy-ish search.
  return needle.split(/\s+/).every((term) => haystack.includes(term));
}

function hasAllTags(item: VaultItem, required: readonly string[]): boolean {
  if (required.length === 0) return true;
  const owned = new Set((item.tags ?? []).map((t) => t.trim()));
  return required.every((t) => owned.has(t.trim()));
}

/**
 * Filter `entries` by any combination of query / folder / tags / kind. Filters
 * are ANDed together; an empty/undefined filter field is ignored. The input
 * array is never mutated.
 */
export function filterEntries(
  entries: readonly VaultEntry[],
  filter: VaultFilter = {},
): VaultEntry[] {
  const folder = filter.folder?.trim();
  const tags = filter.tags ?? [];
  return entries.filter(({ item }) => {
    if (filter.kind && item.kind !== filter.kind) return false;
    if (folder && item.folder?.trim() !== folder) return false;
    if (!hasAllTags(item, tags)) return false;
    if (filter.query && !matchesQuery(item, filter.query)) return false;
    return true;
  });
}

/** Sort keys available for the vault list. */
export type VaultSortKey = 'title' | 'updated' | 'kind';
export type SortDirection = 'asc' | 'desc';

export interface VaultSort {
  key: VaultSortKey;
  direction: SortDirection;
}

/** The default ordering shown to the user: most-recently-updated first. */
export const DEFAULT_VAULT_SORT: VaultSort = { key: 'updated', direction: 'desc' };

function compareByKey(a: VaultEntry, b: VaultEntry, key: VaultSortKey): number {
  switch (key) {
    case 'title':
      return a.item.title.localeCompare(b.item.title, undefined, {
        sensitivity: 'base',
      });
    case 'updated':
      return a.updatedAt.getTime() - b.updatedAt.getTime();
    case 'kind':
      return a.item.kind.localeCompare(b.item.kind);
  }
}

/**
 * Return a new array of `entries` sorted by the given key/direction. Ties are
 * broken by title then id so the order is **stable and deterministic** across
 * renders (important for a predictable UI and for testability). The input array
 * is never mutated.
 */
export function sortEntries(
  entries: readonly VaultEntry[],
  sort: VaultSort = DEFAULT_VAULT_SORT,
): VaultEntry[] {
  const sign = sort.direction === 'asc' ? 1 : -1;
  return [...entries].sort((a, b) => {
    const primary = compareByKey(a, b, sort.key);
    if (primary !== 0) return sign * primary;
    // Deterministic tie-break, independent of sort direction.
    const byTitle = a.item.title.localeCompare(b.item.title, undefined, {
      sensitivity: 'base',
    });
    if (byTitle !== 0) return byTitle;
    return a.id.localeCompare(b.id);
  });
}

/**
 * One-shot convenience: filter then sort. This is the query a vault list view
 * runs on every keystroke / filter change.
 */
export function queryVault(
  entries: readonly VaultEntry[],
  options: { filter?: VaultFilter; sort?: VaultSort } = {},
): VaultEntry[] {
  return sortEntries(filterEntries(entries, options.filter), options.sort);
}
