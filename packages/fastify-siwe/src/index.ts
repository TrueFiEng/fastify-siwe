import cookie from '@fastify/cookie'
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import fp from 'fastify-plugin'
import { SiweMessage } from 'siwe'
import { InMemoryStore } from './InMemoryStore'
import { SiweApi } from './SiweApi'
import { SessionStore } from './types'

export interface FastifySiweOptions {
  store: SessionStore
}

export const signInWithEthereum = ({ store }: FastifySiweOptions) =>
  fp(async (fastify: FastifyInstance) => {
    fastify.addHook('preHandler', async (request, reply) => {
      request.siwe = new SiweApi(store)
    })
  }, { name: 'SIWE' })

export const siweMiddleware = ({ store }: FastifySiweOptions) => 
  async (request: FastifyRequest, reply: FastifyReply, done: (err?: FastifyError) => void) => {
    const token = extractAuthToken(request)
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
  };


export { SessionStore, InMemoryStore }

function extractAuthToken(request: FastifyRequest): string | undefined {
  return request.cookies['authToken']
}

async function parseAndValidateToken(token: string): Promise<SiweMessage> {
  const { message, signature } = JSON.parse(token)

  const siweMessage = new SiweMessage(message)

  await siweMessage.verify({ signature })

  return message
}
