import { expect } from 'chai'
import * as chai from 'chai'
import createFastify, { FastifyInstance } from 'fastify'
import { MockProvider } from 'ethereum-waffle'
import { SiweMessage } from 'siwe'
import { signInWithEthereum } from './plugin'
import { InMemoryStore } from './InMemoryStore'
import cookie from '@fastify/cookie'
import { registerSiweRoutes } from './registerSiweRoutes'
import { Wallet } from 'ethers'
import * as chaiAsPromised from 'chai-as-promised'
import { SessionStore } from './types'
import { getNonce, createAuthMessage, signIn, getAuth } from './utils'

chai.use(chaiAsPromised)

describe.only('Fastify with SIWE API', () => {
  let app: FastifyInstance
  let provider: MockProvider
  let signer: Wallet
  let store: SessionStore
  let defaultMessage: any

  before(async () => {
    provider = new MockProvider({ ganacheOptions: { chain: { chainId: 1 } } as any })
    signer = provider.getWallets()[0]
    app = createFastify()
    defaultMessage = createAuthMessage(signer)

    store = new InMemoryStore()

    void app.register(cookie)
    void app.register(signInWithEthereum({ store }))
    registerSiweRoutes(app)
  })

  after(async () => {
    await app.close()
  })

  it('initializes session', async () => {
    const response = await getNonce(app)
    expect(response.statusCode).to.equal(200)
    const nonce = JSON.parse(response.payload).nonce
    expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)
    expect(await store.get(nonce)).to.deep.equal({ nonce })
  })

  it('authenticates correctly', async () => {
    const response = await getNonce(app)
    const nonce = JSON.parse(response.payload).nonce
    expect(await store.get(nonce)).to.deep.equal({ nonce })

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = await signer.signMessage(message.prepareMessage())

    await signIn(app, { signature, message })

    expect(await store.get(nonce)).to.deep.equal({
      nonce,
      message,
    })

    const authToken = JSON.stringify({ signature, message })

    const authResponse: { loggedIn: boolean; message: SiweMessage } = (await getAuth(app, authToken)).json()

    expect(authResponse.loggedIn).to.equal(true)
    expect(authResponse.message.nonce).to.equal(nonce)
    expect(authResponse.message.address).to.equal(await signer.getAddress())
  })

  it('fails on re-use the same nonce', async () => {
    const secondSigner = provider.getWallets()[1]

    const response = await getNonce(app)
    const nonce = JSON.parse(response.payload).nonce

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = await signer.signMessage(message.prepareMessage())

    await signIn(app, { signature, message })

    const authToken = JSON.stringify({ signature, message })

    const authResponse: { loggedIn: boolean; message: SiweMessage } = (await getAuth(app, authToken)).json()

    expect(authResponse.loggedIn).to.equal(true)
    expect(authResponse.message.nonce).to.equal(nonce)
    expect(authResponse.message.address).to.equal(await signer.getAddress())

    const secondMessage = createAuthMessage(secondSigner)
    const messageWithReusedNonce = new SiweMessage({ ...secondMessage, nonce })
    const signatureWithReusedNonce = await secondSigner.signMessage(messageWithReusedNonce.prepareMessage())

    const signInResponse = await signIn(app, {
      signature: signatureWithReusedNonce,
      message: messageWithReusedNonce,
    })

    expect(signInResponse.statusCode).to.equal(403)
    expect(signInResponse.payload).to.equal('Session already exists')
  })

  it('returns 401 because of invalid token', async () => {
    const authToken = JSON.stringify({
      signature: 'invalid',
      message: 'invalid',
    })

    const authResponse = await getAuth(app, authToken)

    expect(authResponse.statusCode).to.equal(401)
    expect(authResponse.payload).to.equal('Invalid SIWE token')
  })

  it('returns 403 because of not initialized session', async () => {
    const invalidNonce = '0'.repeat(17)
    const message = new SiweMessage({ ...defaultMessage, nonce: invalidNonce })
    const signature = await signer.signMessage(message.prepareMessage())

    const response = await signIn(app, { signature, message })

    expect(response.statusCode).to.equal(403)
    expect(response.payload).to.equal('Session not initialized')
  })

  it('returns 403 because of invalid nonce', async () => {
    const response = await getNonce(app)
    const nonce = JSON.parse(response.payload).nonce

    const message = new SiweMessage({ ...defaultMessage, nonce: nonce.slice(0, -1) })
    const signature = await signer.signMessage(message.prepareMessage())

    const signInResponse = await signIn(app, { signature, message })

    expect(signInResponse.statusCode).to.equal(403)
    expect(signInResponse.payload).to.equal('Session not initialized')
  })

  it('fails on sign in because of invalid signature', async () => {
    const response = await getNonce(app)
    const nonce = JSON.parse(response.payload).nonce

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = 'invalid'

    const signInResponse = await signIn(app, { signature, message })
    expect(signInResponse.statusCode).to.equal(403)
  })

  it('fails on sign in because of invalid message', async () => {
    const response = await getNonce(app)
    const nonce = JSON.parse(response.payload).nonce

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = await signer.signMessage(message.prepareMessage())

    const invalidMessage = new SiweMessage({ ...message, address: '0x0000000000000000000000000000000000000000' })

    const signInResponse = await signIn(app, { signature, message: invalidMessage })
    expect(signInResponse.statusCode).to.equal(403)
  })
})

describe('Fastify with incorrect configuration', () => {
  it('throws an error if @fastify/cookie is not registered', async () => {
    const app = createFastify()
    const store = new InMemoryStore()
    void app.register(signInWithEthereum({ store }))
    registerSiweRoutes(app)

    void expect(app.listen({ port: 8080 })).to.be.rejectedWith(
      '@fastify/cookie is not registered. Please register it before using fastify-siwe'
    )
  })
})
