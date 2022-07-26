import { InMemoryStore } from './InMemoryStore'
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

  it('generates correct nonce', async () => {
    const nonce = await siweApi.generateNonce()
    expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)
  })

  it('sets session', async () => {
    const session = new SiweMessage({
      domain: 'https://example.com',
      address: '0x0000000000000000000000000000000000000000',
      statement: 'Sign in with Ethereum to the app.',
      uri: 'https://example.com',
      version: '1',
      chainId: 1,
      nonce: await siweApi.generateNonce(),
    })

    await siweApi.setSession(session)

    const storedSession = await store.get(session.nonce)

    expect(storedSession).to.exist
    expect(storedSession?.nonce).to.equal(session.nonce)
    expect(storedSession?.address).to.equal(session.address)
  })

  it('destroys session', async () => {
    const session = new SiweMessage({
      domain: 'https://example.com',
      address: '0x0000000000000000000000000000000000000000',
      statement: 'Sign in with Ethereum to the app.',
      uri: 'https://example.com',
      version: '1',
      chainId: 1,
      nonce: await siweApi.generateNonce(),
    })

    await siweApi.setSession(session)

    const storedSession = await store.get(session.nonce)

    expect(storedSession).to.exist
    expect(storedSession?.nonce).to.equal(session.nonce)
    expect(storedSession?.address).to.equal(session.address)

    await siweApi.destroySession()

    const destroyedSession = await store.get(session.nonce)
    expect(destroyedSession).to.be.undefined
    expect(siweApi.session).to.be.undefined
  })
})
