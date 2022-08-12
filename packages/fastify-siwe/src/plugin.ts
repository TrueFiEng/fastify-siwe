import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { SiweApi } from './SiweApi'
import { SessionStore } from './types'
import fastifyPlugin from 'fastify-plugin'
import type {} from '@fastify/cookie' // Has to be there in order to override the Fastify types with cookies.
import { InMemoryStore } from './InMemoryStore'

export interface FastifySiweOptions {
  store?: SessionStore
}

export const signInWithEthereum = ({ store = new InMemoryStore() }: FastifySiweOptions = {}) =>
  fastifyPlugin(
    async (fastify: FastifyInstance) => {
      fastify.addHook('onReady', async () => {
        if (!fastify.parseCookie) {
          throw new Error('@fastify/cookie is not registered. Please register it before using fastify-siwe')
        }
      })

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
        request.siwe = new SiweApi(store)
        const token = request.cookies['__Host_auth_token']
        if (token) {
          try {
            const siweMessage = await parseAndValidateToken(token)

            const currentSession = await store.get(siweMessage.nonce)
            if (!currentSession || siweMessage.nonce !== currentSession.nonce) {
              return reply.status(403).clearCookie('__Host_auth_token').send('Invalid SIWE nonce')
            }

            request.siwe.session = siweMessage
          } catch (err) {
            void reply.status(401).clearCookie('__Host_auth_token').send('Invalid token')
          }
        }
      })
    },
    { name: 'SIWE' }
  )

async function parseAndValidateToken(token: string): Promise<SiweMessage> {
  const { message, signature } = JSON.parse(token)

  const siweMessage = new SiweMessage(message)

  await siweMessage.verify({ signature })

  return message
}
