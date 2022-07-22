import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { SiweApi } from './SiweApi'
import { SessionStore } from './types'
import fastifyPlugin from 'fastify-plugin'
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import type { fastifyCookie } from '@fastify/cookie' // Has to be there in order to override the Fastify types with cookies.

export interface FastifySiweOptions {
  store: SessionStore
}

export const siwePlugin = ({ store }: FastifySiweOptions) =>
  fastifyPlugin(
    async (fastify: FastifyInstance) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
        request.siwe = new SiweApi(store)
      })
    },
    { name: 'SIWE' }
  )

export const siweAuthenticated =
  ({ store }: FastifySiweOptions) =>
  async (request: FastifyRequest, reply: FastifyReply, done: (err?: FastifyError) => void) => {
    const token = request.cookies['authToken']
    if (!token) {
      return reply.code(401).send('Unauthorized')
    }

    try {
      const siweMessage = await parseAndValidateToken(token)

      const currentSession = await store.get(siweMessage.nonce)
      if (!currentSession || siweMessage.nonce !== currentSession.nonce) {
        return reply.status(403).send('Invalid nonce')
      }

      currentSession.message = siweMessage
      await store.save(currentSession)

      request.siwe.session = siweMessage
      done()
    } catch (err) {
      reply.status(401).send('Invalid token')
    }
  }

async function parseAndValidateToken(token: string): Promise<SiweMessage> {
  const { message, signature } = JSON.parse(token)

  const siweMessage = new SiweMessage(message)

  await siweMessage.verify({ signature })

  return message
}
