import { InMemoryStore } from '.'
import { expect } from 'chai'
import { StoredSession } from './types'

describe('InMemoryStore', () => {
  let store: InMemoryStore

  beforeEach(async () => {
    store = new InMemoryStore()
  })

  it('saves StoredSession in memory', async () => {
    const storedSession: StoredSession = {
      nonce: '0123456789abcdefg',
    }
    await store.save(storedSession)

    const session = await store.get(storedSession.nonce)
    expect(session).to.exist
    expect(session?.nonce).to.equal(storedSession.nonce)
  })

  it('returns undefined for non-existent nonce', async () => {
    const nonExistingNonce = '0123456789abcdefg'
    const session = await store.get(nonExistingNonce)
    expect(session).to.be.undefined
  })

  it('returns undefined for non-existent nonce', async () => {
    const nonExistingNonce = '0123456789abcdefg'
    const session = await store.get(nonExistingNonce)
    expect(session).to.be.undefined
  })

  it('deletes session', async () => {
    const storedSession: StoredSession = {
      nonce: '0123456789abcdefg',
    }
    await store.save(storedSession)

    const session = await store.get(storedSession.nonce)
    expect(session).to.exist
    expect(session?.nonce).to.equal(storedSession.nonce)

    await store.remove(storedSession.nonce)
    const removedSession = await store.get(storedSession.nonce)
    expect(removedSession).to.be.undefined
  })
})
