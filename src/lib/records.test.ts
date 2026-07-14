import { describe, expect, it } from 'vitest';
import { getTemplate } from '../data/templates';
import { coerceRecord, createBlankRecord } from './records';

describe('rule record identities', () => {
  const rules = getTemplate('rules');

  it('creates a UUID-backed draft without inventing a readable sequence ID', () => {
    const record = createBlankRecord(rules);

    expect(record.data.rule_id).toBe('');
    expect(record.data.uuid).toMatch(/^[0-9a-f-]{36}$/i);
    expect(record.id).toBe(record.data.uuid);
    expect(record.data).not.toHaveProperty('last_reviewed');
  });

  it('preserves readable IDs and migrates legacy UUID IDs into the UUID field', () => {
    const current = coerceRecord({
      id: 'EXEC-0007',
      data: {
        rule_id: 'EXEC-0007',
        uuid: '08cf5128-3e17-44ce-9087-f27105609360',
        name: 'Current rule',
      },
    }, rules);
    const legacy = coerceRecord({
      id: '08cf5128-3e17-44ce-9087-f27105609360',
      data: {
        rule_id: '08cf5128-3e17-44ce-9087-f27105609360',
        name: 'Legacy rule',
      },
    }, rules);

    expect(current).toMatchObject({ id: 'EXEC-0007', data: { rule_id: 'EXEC-0007' } });
    expect(legacy).toMatchObject({
      id: '08cf5128-3e17-44ce-9087-f27105609360',
      data: {
        rule_id: '',
        uuid: '08cf5128-3e17-44ce-9087-f27105609360',
      },
    });
  });
});
