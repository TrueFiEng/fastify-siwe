import { expect } from 'chai'
import * as chai from 'chai'
import createFastify, { FastifyInstance } from 'fastify'
import { MockProvider } from 'ethereum-waffle'
import { SiweMessage } from 'siwe'
import { siwePlugin } from './plugin'
import { InMemoryStore } from './InMemoryStore'
import cookie from '@fastify/cookie'
import { registerSiweRoutes } from './registerSiweRoutes'
import { Wallet } from 'ethers'
import * as chaiAsPromised from 'chai-as-promised'

chai.use(chaiAsPromised)

describe('Fastify with SIWE API', () => {
  let app: FastifyInstance
  let provider: MockProvider
  let signer: Wallet

  before(async () => {
    provider = new MockProvider({ ganacheOptions: { chain: { chainId: 1 } } as any })
    signer = provider.getWallets()[0]
    app = createFastify()

    const store = new InMemoryStore()

    void app.register(cookie)
    void app.register(siwePlugin({ store }))
    registerSiweRoutes(app, { store })
  })

  it('returns correct nonce', async () => {
    const { nonce } = (
      await app.inject({
        method: 'POST',
        url: '/siwe/init',
      })
    ).json()
    expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)
  })

  it('authenticates correctly', async () => {
    const { nonce } = (
      await app.inject({
        method: 'POST',
        url: '/siwe/init',
      })
    ).json()

    const message = new SiweMessage({
      domain: 'https://example.com',
      address: await signer.getAddress(),
      statement: 'Sign in with Ethereum to the app.',
      uri: 'https://example.com',
      version: '1',
      chainId: 1,
      nonce,
    })
    const signature = await signer.signMessage(message.prepareMessage())

    await app.inject({
      method: 'POST',
      url: '/siwe/signin',
      payload: {
        signature,
        message,
      },
    })

    const authToken = JSON.stringify({ signature, message })

    const authResponse: { loggedIn: boolean; message: SiweMessage } = (
      await app.inject({
        method: 'GET',
        url: '/siwe/me',
        cookies: {
          __Host_auth_token: authToken,
        },
      })
    ).json()

    expect(authResponse.loggedIn).to.equal(true)
    expect(authResponse.message.nonce).to.equal(nonce)
    expect(authResponse.message.address).to.equal(await signer.getAddress())
  })

  it('re-uses the same nonce', async () => {
    const secondSigner = provider.getWallets()[1]

    const { nonce } = (
      await app.inject({
        method: 'POST',
        url: '/siwe/init',
      })
    ).json()

    const message = new SiweMessage({
      domain: 'https://example.com',
      address: await signer.getAddress(),
      statement: 'Sign in with Ethereum to the app.',
      uri: 'https://example.com',
      version: '1',
      chainId: 1,
      nonce,
    })

    const signature = await signer.signMessage(message.prepareMessage())
    const authToken = JSON.stringify({ signature, message })

    await app.inject({
      method: 'POST',
      url: '/siwe/signin',
      payload: {
        signature,
        message,
      },
    })

    const authResponse: { loggedIn: boolean; message: SiweMessage } = (
      await app.inject({
        method: 'GET',
        url: '/siwe/me',
        cookies: {
          __Host_auth_token: authToken,
        },
      })
    ).json()

    expect(authResponse.loggedIn).to.equal(true)
    expect(authResponse.message.nonce).to.equal(nonce)
    expect(authResponse.message.address).to.equal(await signer.getAddress())

    const messageWithReusedNonce = new SiweMessage({
      domain: 'https://example.com',
      address: await secondSigner.getAddress(),
      statement: 'Sign in with Ethereum to the app.',
      uri: 'https://example.com',
      version: '1',
      chainId: 1,
      nonce,
    })

    const signatureWithReusedNonce = await secondSigner.signMessage(messageWithReusedNonce.prepareMessage())

    const secondAuthToken = JSON.stringify({ signature: signatureWithReusedNonce, message: messageWithReusedNonce })

    const secondAuthResponse = await app.inject({
      method: 'GET',
      url: '/siwe/me',
      cookies: {
        __Host_auth_token: secondAuthToken,
      },
    })

    expect(secondAuthResponse.statusCode).to.equal(403)
    expect(secondAuthResponse.payload).to.equal('Invalid address')
  })

  it('returns 401 because of missing token', async () => {
    const authResponse = await app.inject({
      method: 'GET',
      url: '/siwe/me',
    })

    expect(authResponse.statusCode).to.equal(401)
    expect(authResponse.body).to.equal('Unauthorized')
  })

  it('returns 401 because of invalid token', async () => {
    const authToken = 'invalid'

    const authResponse = await app.inject({
      method: 'GET',
      url: '/siwe/me',
      cookies: {
        __Host_auth_token: authToken,
      },
    })

    expect(authResponse.statusCode).to.equal(401)
    expect(authResponse.body).to.equal('Invalid token')
  })

  it('returns 403 because of invalid nonce', async () => {
    const invalidNonce = '0'.repeat(17)
    const message = new SiweMessage({
      domain: 'https://example.com',
      address: await signer.getAddress(),
      statement: 'Sign in with Ethereum to the app.',
      uri: 'https://example.com',
      version: '1',
      chainId: 1,
      nonce: invalidNonce,
    })

    const signature = await signer.signMessage(message.prepareMessage())
    const authToken = JSON.stringify({ signature, message })

    const authResponse = await app.inject({
      method: 'GET',
      url: '/siwe/me',
      cookies: {
        __Host_auth_token: authToken,
      },
    })

    expect(authResponse.statusCode).to.equal(403)
    expect(authResponse.payload).to.equal('Invalid nonce')
  })

  it('2 apis should generate different nonces', async () => {
    const secondApp = createFastify()

    const store = new InMemoryStore()

    void secondApp.register(cookie)
    void secondApp.register(siwePlugin({ store }))
    registerSiweRoutes(secondApp, { store })

    const firstPromise = app.inject({
      method: 'POST',
      url: '/siwe/init',
    })

    const secondPromise = secondApp.inject({
      method: 'POST',
      url: '/siwe/init',
    })

    const [firstResponse, secondResponse] = await Promise.all([firstPromise, secondPromise])

    expect(firstResponse.statusCode).to.equal(200)
    expect(secondResponse.statusCode).to.equal(200)
    expect(firstResponse.json().nonce).to.not.equal(secondResponse.json().nonce)
  })
})

describe('Fastify with incorrect configuration', () => {
  it('throws an error if @fastify/cookie is not registered', async () => {
    const app = createFastify()
    const store = new InMemoryStore()
    void app.register(siwePlugin({ store }))
    registerSiweRoutes(app, { store })

    void expect(app.listen({ port: 8080 })).to.be.rejectedWith(
      '@fastify/cookie is not registered. Please register it before using fastify-siwe'
    )
  })
})
