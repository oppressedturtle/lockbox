import { describe, it, expect } from 'vitest';
import {
  collectFolders,
  collectTags,
  filterEntries,
  sortEntries,
  queryVault,
  DEFAULT_VAULT_SORT,
  type VaultEntry,
} from './query';
import type { VaultItem, VaultItemInput } from './schema';
import { vaultItemSchema } from './schema';

/** Build a fully-defaulted VaultItem from partial input (applies schema defaults). */
function makeItem(input: VaultItemInput): VaultItem {
  return vaultItemSchema.parse(input);
}

let seq = 0;
function entry(
  input: VaultItemInput,
  meta: { id?: string; version?: number; updatedAt?: Date } = {},
): VaultEntry {
  seq += 1;
  return {
    id: meta.id ?? `00000000-0000-0000-0000-${String(seq).padStart(12, '0')}`,
    item: makeItem(input),
    version: meta.version ?? 1,
    updatedAt: meta.updatedAt ?? new Date('2026-01-01T00:00:00Z'),
  };
}

const gmail = entry({
  v: 1,
  kind: 'login',
  title: 'Gmail',
  folder: 'Personal',
  tags: ['email', 'important'],
  username: 'me@gmail.com',
  password: 'super-secret-pw',
  url: 'https://mail.google.com',
});
const github = entry({
  v: 1,
  kind: 'login',
  title: 'GitHub',
  folder: 'Work',
  tags: ['dev', 'important'],
  username: 'octocat',
  url: 'https://github.com',
});
const wifi = entry({
  v: 1,
  kind: 'note',
  title: 'Home WiFi',
  folder: 'Personal',
  tags: ['network'],
  body: 'ssid: frognet passphrase: hunter2',
});
const visa = entry({
  v: 1,
  kind: 'card',
  title: 'Visa',
  tags: ['finance'],
  cardholderName: 'Yanis',
  number: '4111 1111 1111 4242',
  cvv: '999',
});

const all = [gmail, github, wifi, visa];

describe('collectFolders', () => {
  it('counts distinct folders and sorts alphabetically', () => {
    expect(collectFolders(all)).toEqual([
      { name: 'Personal', count: 2 },
      { name: 'Work', count: 1 },
    ]);
  });

  it('omits entries with no folder', () => {
    // visa has no folder → not represented
    const names = collectFolders(all).map((f) => f.name);
    expect(names).not.toContain('');
    expect(collectFolders([visa])).toEqual([]);
  });
});

describe('collectTags', () => {
  it('counts tags across entries, most-used first', () => {
    expect(collectTags(all)).toEqual([
      { tag: 'important', count: 2 },
      { tag: 'dev', count: 1 },
      { tag: 'email', count: 1 },
      { tag: 'finance', count: 1 },
      { tag: 'network', count: 1 },
    ]);
  });

  it('counts a duplicated tag on one entry only once', () => {
    const dup = entry({
      v: 1,
      kind: 'note',
      title: 'Dup',
      tags: ['x', 'x', 'x'],
      body: '',
    });
    expect(collectTags([dup])).toEqual([{ tag: 'x', count: 1 }]);
  });
});

describe('filterEntries', () => {
  it('returns everything for an empty filter', () => {
    expect(filterEntries(all)).toHaveLength(4);
  });

  it('filters by kind', () => {
    expect(filterEntries(all, { kind: 'login' })).toEqual([gmail, github]);
  });

  it('filters by exact folder', () => {
    expect(filterEntries(all, { folder: 'Personal' })).toEqual([gmail, wifi]);
  });

  it('requires ALL tags (AND)', () => {
    expect(filterEntries(all, { tags: ['important'] })).toEqual([gmail, github]);
    expect(filterEntries(all, { tags: ['important', 'dev'] })).toEqual([github]);
  });

  it('matches a case-insensitive query against title', () => {
    expect(filterEntries(all, { query: 'git' })).toEqual([github]);
  });

  it('matches searchable login fields (username, url) but not the password', () => {
    expect(filterEntries(all, { query: 'octocat' })).toEqual([github]);
    expect(filterEntries(all, { query: 'mail.google.com' })).toEqual([gmail]);
    // password is intentionally NOT in the haystack
    expect(filterEntries(all, { query: 'super-secret-pw' })).toEqual([]);
  });

  it('matches note bodies', () => {
    expect(filterEntries(all, { query: 'frognet' })).toEqual([wifi]);
  });

  it('matches only the last 4 card digits, never the full PAN', () => {
    expect(filterEntries(all, { query: '4242' })).toEqual([visa]);
    expect(filterEntries(all, { query: '4111' })).toEqual([]);
    // CVV must never match
    expect(filterEntries(all, { query: '999' })).toEqual([]);
  });

  it('ANDs multiple query terms across fields', () => {
    // "important" is a tag on both logins; "github" narrows to one
    expect(filterEntries(all, { query: 'important github' })).toEqual([github]);
  });

  it('combines filters (AND)', () => {
    expect(filterEntries(all, { kind: 'login', folder: 'Personal', query: 'gmail' })).toEqual([
      gmail,
    ]);
    expect(filterEntries(all, { kind: 'card', folder: 'Personal' })).toEqual([]);
  });

  it('does not mutate the input', () => {
    const copy = [...all];
    filterEntries(all, { kind: 'login' });
    expect(all).toEqual(copy);
  });
});

describe('sortEntries', () => {
  const a = entry(
    { v: 1, kind: 'note', title: 'Apple', body: '' },
    { updatedAt: new Date('2026-03-01T00:00:00Z') },
  );
  const b = entry(
    { v: 1, kind: 'note', title: 'banana', body: '' },
    { updatedAt: new Date('2026-01-01T00:00:00Z') },
  );
  const c = entry(
    { v: 1, kind: 'note', title: 'Cherry', body: '' },
    { updatedAt: new Date('2026-02-01T00:00:00Z') },
  );
  const items = [b, c, a];

  it('sorts by title ascending, case-insensitively', () => {
    expect(sortEntries(items, { key: 'title', direction: 'asc' })).toEqual([a, b, c]);
  });

  it('sorts by title descending', () => {
    expect(sortEntries(items, { key: 'title', direction: 'desc' })).toEqual([c, b, a]);
  });

  it('defaults to most-recently-updated first', () => {
    expect(sortEntries(items)).toEqual([a, c, b]);
    expect(DEFAULT_VAULT_SORT).toEqual({ key: 'updated', direction: 'desc' });
  });

  it('breaks ties deterministically by title then id', () => {
    const t = new Date('2026-01-01T00:00:00Z');
    const x = entry({ v: 1, kind: 'note', title: 'Same', body: '' }, { id: 'b', updatedAt: t });
    const y = entry({ v: 1, kind: 'note', title: 'Same', body: '' }, { id: 'a', updatedAt: t });
    // same updatedAt + same title → id 'a' before 'b', regardless of direction
    expect(sortEntries([x, y], { key: 'updated', direction: 'desc' })).toEqual([y, x]);
    expect(sortEntries([x, y], { key: 'updated', direction: 'asc' })).toEqual([y, x]);
  });

  it('does not mutate the input', () => {
    const copy = [...items];
    sortEntries(items, { key: 'title', direction: 'asc' });
    expect(items).toEqual(copy);
  });
});

describe('queryVault', () => {
  it('filters then sorts in one pass', () => {
    const older = entry(
      { v: 1, kind: 'login', title: 'Alpha', tags: ['t'], username: '', password: '' },
      { updatedAt: new Date('2026-01-01T00:00:00Z') },
    );
    const newer = entry(
      { v: 1, kind: 'login', title: 'Beta', tags: ['t'], username: '', password: '' },
      { updatedAt: new Date('2026-05-01T00:00:00Z') },
    );
    const other = entry({ v: 1, kind: 'note', title: 'Gamma', tags: ['t'], body: '' });
    const result = queryVault([older, newer, other], {
      filter: { kind: 'login', tags: ['t'] },
      sort: { key: 'updated', direction: 'desc' },
    });
    expect(result).toEqual([newer, older]);
  });
});
