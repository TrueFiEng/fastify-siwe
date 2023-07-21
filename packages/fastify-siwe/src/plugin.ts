import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { SiweApi } from './SiweApi'
import { SessionStore, Token } from './types'
import fastifyPlugin from 'fastify-plugin'
import type {} from '@fastify/cookie' // Has to be there in order to override the Fastify types with cookies.
import { InMemoryStore } from './InMemoryStore'
import { ethers, utils } from 'ethers'
import { GNOSIS_SAFE_ABI } from './constants'
import { RegisterSiweRoutesOpts, registerSiweRoutes } from './registerSiweRoutes'

export interface FastifySiweOptions {
  infuraId?: string
  store?: SessionStore
}

const defaultOpts: RegisterSiweRoutesOpts = {
  cookieSecure: process.env.NODE_ENV !== 'development',
  cookieSameSite: 'strict',
  cookieMaxAge: undefined,
  cookiePath: '/',
}

export const signInWithEthereum = (
  { store = new InMemoryStore(), infuraId }: FastifySiweOptions = {},
  {
    cookieSecure = defaultOpts.cookieSecure,
    cookieSameSite = defaultOpts.cookieSameSite,
    cookieMaxAge = defaultOpts.cookieMaxAge,
    cookiePath = defaultOpts.cookiePath,
  }: RegisterSiweRoutesOpts = defaultOpts
) =>
  fastifyPlugin(
    async (fastify: FastifyInstance) => {
      fastify.addHook('onReady', async () => {
        if (!fastify.parseCookie) {
          throw new Error('@fastify/cookie is not registered. Please register it before using fastify-siwe')
        }
      })

      registerSiweRoutes(fastify, { cookieSecure, cookieSameSite, cookieMaxAge, cookiePath, infuraId })

      fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
        request.siwe = new SiweApi(store)
        const multichainHeader = request.headers['multichain'] as string | undefined
        const [address, chainId] = multichainHeader?.split(':') ?? []
        const tokenCookie = request.cookies[`__Host_authToken${address}${chainId}`]
        if (!chainId || !address || !tokenCookie) return

        const path = request?.routerPath
        if (path === '/siwe/init' || path === '/siwe/signin') return

        let token: Token | undefined = undefined
        try {
          token = JSON.parse(tokenCookie) as Token
          const siweMessage = await validateToken(token, infuraId)

          const currentSession = await store.get(siweMessage.nonce)
          if (!currentSession?.message || currentSession.message.address !== siweMessage.address) {
            return reply
              .status(403)
              .clearCookie(`__Host_authToken${address}${chainId}`, {
                secure: cookieSecure,
                sameSite: cookieSameSite,
                path: cookiePath,
              })
              .send('Invalid SIWE nonce')
          }
          request.siwe.session = siweMessage
        } catch (err) {
          if (!token) return
          void reply
            .status(401)
            .clearCookie(`__Host_authToken${address}${chainId}`, {
              secure: cookieSecure,
              sameSite: cookieSameSite,
              path: cookiePath,
            })
            .send('Invalid SIWE token')
        }
      })
    },
    { name: 'SIWE' }
  )

export async function validateToken(token: Token, infuraId?: string): Promise<SiweMessage> {
  const { signature, message } = token
  const siweMessage = new SiweMessage(message)
  let valid = false

  try {
    await siweMessage.verify({ signature })
    valid = true
  } catch {} // eslint-disable-line no-empty

  try {
    await verifyGnosisSafeSignature(siweMessage, signature, infuraId)
    valid = true
  } catch {} // eslint-disable-line no-empty

  if (!valid) {
    throw new Error('Invalid SIWE token')
  }
  return siweMessage
}

async function verifyGnosisSafeSignature(message: SiweMessage, signature: string, infuraId?: string) {
  const provider = infuraId
    ? new ethers.providers.InfuraProvider(message.chainId, infuraId)
    : ethers.providers.getDefaultProvider(message.chainId)
  const contract = new ethers.Contract(message.address, new utils.Interface(GNOSIS_SAFE_ABI), provider)
  const hashedMessage = utils.hashMessage(message.prepareMessage())
  const msgHash = await contract.getMessageHash(hashedMessage, { from: message.address })
  await contract.checkSignatures(msgHash, hashedMessage, signature)
}
