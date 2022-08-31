import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { SiweApi } from './SiweApi'
import { SessionStore, Token, TokenSet } from './types'
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

      fastify.addHook(
        'preHandler',
        async (
          request: FastifyRequest<{
            Querystring: {
              chainId?: number
              address?: string
            }
          }>,
          reply: FastifyReply
        ) => {
          request.siwe = new SiweApi(store)

          const { chainId, address } = request.query
          const tokenSetCookie = request.cookies['__Host_token_set']
          if (!chainId || !address || !tokenSetCookie) return

          const path = request?.routerPath

          if (path === '/siwe/init' || path === '/siwe/signin') return

          let tokenSet: TokenSet | undefined = undefined
          let token: Token | undefined = undefined
          try {
            tokenSet = JSON.parse(tokenSetCookie) as TokenSet
            token = tokenSet[chainId]?.[address]
            console.log('========================================================')
            console.log({ tokenSet, token })
            console.log('========================================================')
            if (!token) return
            const { signature, message } = token

            if (signature === '0x') {
              await validateContract(message)
            }

            const siweMessage = await validateToken(token)

            console.log({ siweMessage })

            const currentSession = await store.get(siweMessage.nonce)
            if (!currentSession?.message || currentSession.message.address !== siweMessage.address) {
              delete tokenSet[chainId][address]
              return reply
                .status(403)
                .setCookie('__Host_token_set', JSON.stringify(tokenSet), {
                  httpOnly: true,
                  secure: cookieSecure,
                  sameSite: cookieSameSite,
                  maxAge: cookieMaxAge,
                  path: cookiePath,
                })
                .send('Invalid SIWE nonce')
            }

            request.siwe.session = siweMessage
          } catch (err) {
            if (!tokenSet || !token) return
            void reply.status(401).send('Invalid SIWE token')
          }

          async function validateContract(message: SiweMessage) {
            const siweMessage = new SiweMessage(message)

            const currentSession = await store.get(siweMessage.nonce)

            if (!currentSession) {
              return reply
                .status(403)
                .clearCookie('__Host_token_set', {
                  secure: cookieSecure,
                  sameSite: cookieSameSite,
                })
                .send()
            }

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
        }
      )
    },
    { name: 'SIWE' }
  )

export async function validateToken(token: Token): Promise<SiweMessage> {
  const { signature, message } = token
  try {
    const siweMessage = new SiweMessage(message)
    await siweMessage.verify({ signature })
  } catch (err) {
    throw new Error('Invalid SIWE tokens')
  }

  return message
}
