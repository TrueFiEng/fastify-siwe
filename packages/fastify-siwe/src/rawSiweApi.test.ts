import { InMemoryStore } from '.'
import { SiweApi } from './SiweApi'
import { expect } from 'chai'
import { SiweMessage } from 'siwe'

describe('SiweApi', () => {
  let store: InMemoryStore
  let siweApi: SiweApi

  beforeEach(async () => {
    store = new InMemoryStore()
    siweApi = new SiweApi(store)
  })

  it('generates correct nonce and saves to store', async () => {
    const nonce = await siweApi.generateNonce()
    expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)

    const session = await store.get(nonce)
    expect(session).to.exist
    expect(session?.nonce).to.equal(nonce)
  })

  it('destroysSession', async () => {
    const nonce = await siweApi.generateNonce()
    const session = await store.get(nonce)
    expect(session).to.exist
    expect(session?.nonce).to.equal(nonce)

    const siweMessage = new SiweMessage({
      domain: 'https://example.com',
      address: '0x0000000000000000000000000000000000000000',
      uri: 'https://example.com',
      version: '1',
      chainId: 1,
      nonce,
    })
    if (session?.message) {
      session.message = siweMessage
    }
    siweApi.session = siweMessage

    await siweApi.destroySession()

    const destroyedSession = await store.get(nonce)
    expect(destroyedSession).to.be.undefined
    expect(siweApi.session).to.be.undefined
  })
})
