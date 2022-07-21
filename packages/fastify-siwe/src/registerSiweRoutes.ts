import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SessionStore } from './types'
import { SiweMessage } from 'siwe'
import { siweAuthenticated } from './index'

export interface RegisterSiweRoutesOpts {
  store: SessionStore
}

export const registerSiweRoutes = (fastify: FastifyInstance, { store }: RegisterSiweRoutesOpts) => {
  fastify.post(
    '/siwe/init',
    {},
    async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
      reply.send({
        nonce: await req.siwe.generateNonce(),
      })
    }
  )

  fastify.post(
    '/siwe/cookie',
    {},
    async function handler(
      this: FastifyInstance,
      req: FastifyRequest<{
        Body: {
          signature: string
          message: SiweMessage
        }
      }>,
      reply: FastifyReply
    ) {
      const authToken = JSON.stringify({
        message: req.body.message,
        signature: req.body.signature,
      })

      reply
        .setCookie('authToken', authToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 1000 * 60 * 60 * 24,
          path: '/',
        })
        .send()
    }
  )

  fastify.get(
    '/siwe/me',
    { preHandler: siweAuthenticated({ store }) },
    async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
      if (!req.siwe.session) {
        reply.status(401).send()
        return
      }

      reply.code(200).send({
        loggedIn: true,
        message: req.siwe.session,
      })
    }
  )

  fastify.get(
    '/siwe/signout',
    {},
    async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
      reply.clearCookie('authToken').send({
        loggedIn: false,
      })
    }
  )

  return fastify
}
