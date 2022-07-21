import { expect } from 'chai'
import createFastify, { FastifyInstance } from 'fastify'
import { MockProvider } from 'ethereum-waffle'
import { SiweMessage } from 'siwe'
import { siwePlugin } from './plugin'
import { InMemoryStore } from './InMemoryStore'
import cookie from '@fastify/cookie'
import { registerSiweRoutes } from './registerSiweRoutes'
import { Wallet } from 'ethers'

describe('Fastify with SIWE API', () => {
  let app: FastifyInstance
  let signer: Wallet

  before(async () => {
    const provider = new MockProvider({ ganacheOptions: { chain: { chainId: 1 } } as any })
    signer = provider.getWallets()[0]
    app = createFastify()

    const store = new InMemoryStore()

    app.register(cookie)
    app.register(siwePlugin({ store }))
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

    const domain = 'https://example.com'
    const origin = 'https://example.com'
    const statement = 'Sign in with Ethereum to the app.'

    const message = new SiweMessage({
      domain,
      address: await signer.getAddress(),
      statement,
      uri: origin,
      version: '1',
      chainId: 1,
      nonce,
    })

    const signature = await signer.signMessage(message.prepareMessage())
    const authToken = JSON.stringify({ signature, message })

    const authResponse = (
      await app.inject({
        method: 'GET',
        url: '/siwe/me',
        cookies: {
          authToken,
        },
      })
    ).json()

    expect(authResponse.loggedIn).to.equal(true)
    expect(authResponse.message).to.deep.equal(message)
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
        authToken,
      },
    })

    expect(authResponse.statusCode).to.equal(401)
    expect(authResponse.body).to.equal('Invalid token')
  })

  it('returns 403 because of invalid nonce', async () => {
    const domain = 'https://example.com'
    const origin = 'https://example.com'
    const statement = 'Sign in with Ethereum to the app.'

    const invalidNonce = '0'.repeat(17)
    const message = new SiweMessage({
      domain,
      address: await signer.getAddress(),
      statement,
      uri: origin,
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
        authToken,
      },
    })

    expect(authResponse.statusCode).to.equal(403)
    expect(authResponse.payload).to.equal('Invalid nonce')
  })
})

describe('Fastify with incorrect configuration', () => {
  // const app = mock()
  // const provider = new MockProvider({ ganacheOptions: { chain: { chainId: 1 } } as any })
  // const signer = provider.getWallets()[0]
  // const fastify = createFastify(opts)
  // const store = new InMemoryStore()
  /**
   * Oops, the user forgot to register the cookie plugin.
   */
  // fastify.register(cookie)
})
