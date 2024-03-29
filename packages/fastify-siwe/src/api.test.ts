import { expect } from 'chai'
import * as chai from 'chai'
import createFastify, { FastifyInstance } from 'fastify'
import { MockProvider } from 'ethereum-waffle'
import { SiweMessage } from 'siwe'
import { signInWithEthereum } from './plugin'
import { InMemoryStore } from './InMemoryStore'
import cookie from '@fastify/cookie'
import { Wallet } from 'ethers'
import * as chaiAsPromised from 'chai-as-promised'
import { SessionStore } from './types'
import { getNonce, createAuthMessage, signIn, getAuth, authenticate, signOut, UserInfo } from './testUtils'

chai.use(chaiAsPromised)

describe('Fastify with SIWE API', () => {
  let app: FastifyInstance
  let provider: MockProvider
  let signer: Wallet
  let store: SessionStore
  let defaultMessage: any

  before(async () => {
    provider = new MockProvider({ ganacheOptions: { chain: { chainId: 1 } } as any })
    signer = provider.getWallets()[0]
    app = createFastify()
    defaultMessage = await createAuthMessage(signer)

    store = new InMemoryStore()

    void app.register(cookie)
    void app.register(signInWithEthereum({ store }))
  })

  after(async () => {
    await app.close()
  })

  it('initializes session', async () => {
    const response = await getNonce(app)
    expect(response.statusCode).to.equal(200)
    const { nonce } = JSON.parse(response.payload)
    expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)
    expect(await store.get(nonce)).to.deep.equal({ nonce })
  })

  it('authenticates correctly', async () => {
    const { nonce } = JSON.parse((await getNonce(app)).payload)
    expect(await store.get(nonce)).to.deep.equal({ nonce })

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = await signer.signMessage(message.prepareMessage())

    const signInResponse = await signIn(app, { signature, message })
    expect(signInResponse.statusCode).to.equal(200)
    expect(signInResponse.headers['set-cookie']).to.exist
    expect(await store.get(nonce)).to.deep.equal({
      nonce,
      message,
    })

    const authToken = JSON.stringify({ signature, message })

    const userInfo: UserInfo = {
      chainId: await signer.getChainId(),
      address: await signer.getAddress(),
    }

    const authResponse: { loggedIn: boolean; message: SiweMessage } = (await getAuth(app, authToken, userInfo)).json()

    expect(authResponse.loggedIn).to.equal(true)
    expect(authResponse.message.nonce).to.equal(nonce)
    expect(authResponse.message.address).to.equal(await signer.getAddress())
  })

  it('fails because of not signed in', async () => {
    const { nonce } = JSON.parse((await getNonce(app)).payload)

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = await signer.signMessage(message.prepareMessage())

    const authToken = JSON.stringify({ signature, message })

    const userInfo: UserInfo = {
      chainId: await signer.getChainId(),
      address: await signer.getAddress(),
    }

    const authResponse = await getAuth(app, authToken, userInfo)

    expect(authResponse.statusCode).to.equal(403)
    expect(authResponse.payload).to.equal('Invalid SIWE nonce')
  })

  it('fails on re-using the same nonce during signing in', async () => {
    const { nonce } = JSON.parse((await getNonce(app)).payload)
    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = await signer.signMessage(message.prepareMessage())
    await signIn(app, { signature, message })
    const authToken = JSON.stringify({ signature, message })

    const userInfo: UserInfo = {
      chainId: await signer.getChainId(),
      address: await signer.getAddress(),
    }

    const authResponse: { loggedIn: boolean; message: SiweMessage } = (await getAuth(app, authToken, userInfo)).json()

    expect(authResponse.loggedIn).to.equal(true)
    expect(authResponse.message.nonce).to.equal(nonce)
    expect(authResponse.message.address).to.equal(await signer.getAddress())

    const secondSigner = provider.getWallets()[1]
    const secondMessage = await createAuthMessage(secondSigner)
    const messageWithReusedNonce = new SiweMessage({ ...secondMessage, nonce })
    const signatureWithReusedNonce = await secondSigner.signMessage(messageWithReusedNonce.prepareMessage())
    const signInResponse = await signIn(app, {
      signature: signatureWithReusedNonce,
      message: messageWithReusedNonce,
    })

    expect(signInResponse.statusCode).to.equal(403)
    expect(signInResponse.payload).to.equal('Session already exists')
  })

  it('fails on signing in because of of not initialized session', async () => {
    const invalidNonce = '0'.repeat(17)
    const message = new SiweMessage({ ...defaultMessage, nonce: invalidNonce })
    const signature = await signer.signMessage(message.prepareMessage())

    const response = await signIn(app, { signature, message })

    expect(response.statusCode).to.equal(403)
    expect(response.payload).to.equal('Session not initialized')
  })

  it('fails on signing in because of invalid nonce', async () => {
    const { nonce } = JSON.parse((await getNonce(app)).payload)

    const message = new SiweMessage({ ...defaultMessage, nonce: nonce.slice(0, -1) })
    const signature = await signer.signMessage(message.prepareMessage())

    const signInResponse = await signIn(app, { signature, message })

    expect(signInResponse.statusCode).to.equal(403)
    expect(signInResponse.payload).to.equal('Session not initialized')
  })

  it('fails on signing in because of invalid signature', async () => {
    const { nonce } = JSON.parse((await getNonce(app)).payload)

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = 'invalid'

    const signInResponse = await signIn(app, { signature, message })
    expect(signInResponse.statusCode).to.equal(403)
    expect(signInResponse.payload).to.equal('Invalid SIWE token')
  })

  it('fails on signing in because of invalid message', async () => {
    const { nonce } = JSON.parse((await getNonce(app)).payload)

    const message = new SiweMessage({ ...defaultMessage, nonce })
    const signature = await signer.signMessage(message.prepareMessage())

    const invalidMessage = new SiweMessage({ ...message, address: '0x0000000000000000000000000000000000000000' })

    const signInResponse = await signIn(app, { signature, message: invalidMessage })
    expect(signInResponse.statusCode).to.equal(403)
    expect(signInResponse.payload).to.equal('Invalid SIWE token')
  })

  it('fails because of invalid nonce', async () => {
    const token = await authenticate(signer, app)
    const { signature, message } = JSON.parse(token)
    const messageWithInvalidNonce = new SiweMessage({ ...message, nonce: '0'.repeat(17) })
    const badToken = JSON.stringify({ signature, message: messageWithInvalidNonce })
    const userInfo: UserInfo = {
      chainId: await signer.getChainId(),
      address: await signer.getAddress(),
    }
    const response = await getAuth(app, badToken, userInfo)
    expect(response.statusCode).to.equal(401)
    expect(response.payload).to.equal('Invalid SIWE token')
  })

  it('fails on protected route because of missing token', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/siwe/me',
      validate: true,
      cookies: {},
    })
    expect(response.statusCode).to.equal(401)
  })

  it('fails because of not being session owner', async () => {
    const token = await authenticate(signer, app)
    const { message } = JSON.parse(token)

    const secondSigner = provider.getWallets()[1]
    const secondMessage = await createAuthMessage(secondSigner)
    const badMessage = new SiweMessage({ ...secondMessage, nonce: message.nonce })
    const badSignature = await secondSigner.signMessage(badMessage.prepareMessage())
    const badToken = JSON.stringify({ signature: badSignature, message: badMessage })
    const userInfo: UserInfo = {
      chainId: await signer.getChainId(),
      address: await signer.getAddress(),
    }
    const response = await getAuth(app, badToken, userInfo)
    expect(response.statusCode).to.equal(403)
    expect(response.payload).to.equal('Invalid SIWE nonce')
  })

  it('fails on getting auth because session does not exist', async () => {
    const message = new SiweMessage({ ...defaultMessage, nonce: '0'.repeat(17) })
    const signature = await signer.signMessage(message.prepareMessage())
    const badToken = JSON.stringify({ signature, message })
    const userInfo: UserInfo = {
      chainId: await signer.getChainId(),
      address: await signer.getAddress(),
    }
    const response = await getAuth(app, badToken, userInfo)
    expect(response.statusCode).to.equal(403)
    expect(response.payload).to.equal('Invalid SIWE nonce')
  })

  it('signs out correctly', async () => {
    const token = await authenticate(signer, app)
    const { message } = JSON.parse(token)
    expect(await store.get(message.nonce)).to.exist
    const userInfo: UserInfo = {
      chainId: await signer.getChainId(),
      address: await signer.getAddress(),
    }
    const response = await signOut(app, token, userInfo)
    expect(response.statusCode).to.equal(200)
    expect(response.headers['set-cookie']).to.exist
    expect(await store.get(message.nonce)).to.not.exist
  })
})

describe('Fastify with incorrect configuration', () => {
  it('throws an error if @fastify/cookie is not registered', async () => {
    const app = createFastify()
    const store = new InMemoryStore()
    void app.register(signInWithEthereum({ store }))

    void expect(app.listen({ port: 8080 })).to.be.rejectedWith(
      '@fastify/cookie is not registered. Please register it before using fastify-siwe'
    )
  })
})
