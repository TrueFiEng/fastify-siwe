import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { SiweApi } from './SiweApi'
import { SessionStore } from './types'
import fastifyPlugin from 'fastify-plugin'
import type {} from '@fastify/cookie' // Has to be there in order to override the Fastify types with cookies.
import { InMemoryStore } from './InMemoryStore'
import { ethers, utils } from 'ethers'
import { EIP1271_MAGIC_VALUE, GNOSIS_SAFE_ABI } from './constants'
import { RegisterSiweRoutesOpts, registerSiweRoutes } from './registerSiweRoutes'

export interface FastifySiweOptions {
  store?: SessionStore
}

const defaultOpts: RegisterSiweRoutesOpts = {
  cookieSecure: process.env.NODE_ENV !== 'development',
  cookieSameSite: 'strict',
  cookieMaxAge: undefined,
  cookiePath: '/',
}

export const signInWithEthereum = (
  { store = new InMemoryStore() }: FastifySiweOptions = {},
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

      registerSiweRoutes(fastify, { cookieSecure, cookieSameSite, cookieMaxAge, cookiePath })

      fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
        request.siwe = new SiweApi(store)
        const token = request.cookies['__Host_auth_token']
        if (token) {
          try {
            const { message, signature } = JSON.parse(token)

            if (signature === '0x') {
              const siweMessage = new SiweMessage(message)

              const currentSession = await store.get(siweMessage.nonce)

              if (!currentSession) {
                return reply
                  .status(403)
                  .clearCookie('__Host_auth_token', {
                    secure: cookieSecure,
                    sameSite: cookieSameSite,
                  })
                  .send()
              }

              const path = request?.routerPath
              if (path === '/siwe/signout') {
                request.siwe.session = siweMessage
                return
              }

              const provider = ethers.getDefaultProvider(message.chainId)
              const contract = new ethers.Contract(message.address, new utils.Interface(GNOSIS_SAFE_ABI), provider)

              const msgHash = utils.hashMessage(siweMessage.prepareMessage())
              let value: string | undefined
              try {
                value = await contract.isValidSignature(msgHash, '0x')
              } catch (err) {
                console.error(err)
              }
              if (value !== EIP1271_MAGIC_VALUE) {
                return reply.status(403).send()
              }
              request.siwe.session = siweMessage
              return
            }

            const siweMessage = await parseAndValidateToken(token)

            const currentSession = await store.get(siweMessage.nonce)
            if (!currentSession?.message || currentSession.message.address !== siweMessage.address) {
              return reply
                .status(403)
                .clearCookie('__Host_auth_token', {
                  secure: cookieSecure,
                  sameSite: cookieSameSite,
                })
                .send('Invalid SIWE nonce')
            }

            request.siwe.session = siweMessage
          } catch (err) {
            void reply
              .status(401)
              .clearCookie('__Host_auth_token', {
                secure: cookieSecure,
                sameSite: cookieSameSite,
              })
              .send('Invalid SIWE token')
          }
        }
      })
    },
    { name: 'SIWE' }
  )

export async function parseAndValidateToken(token: string): Promise<SiweMessage> {
  const { message, signature } = JSON.parse(token)

  try {
    const siweMessage = new SiweMessage(message)
    await siweMessage.verify({ signature })
  } catch (err) {
    throw new Error('Invalid SIWE token')
  }

  return message
}
