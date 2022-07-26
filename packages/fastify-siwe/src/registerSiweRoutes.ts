import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SessionStore } from './types'
import { SiweMessage } from 'siwe'
import { siweAuthenticated } from './index'

export interface RegisterSiweRoutesOpts {
  store: SessionStore
  cookieSameSite?: boolean | 'strict' | 'lax' | 'none'
  cookieMaxAge?: number
  cookiePath?: string
}

const DEFAULT_COOKIE_SAME_SITE = 'strict'
const DEFAULT_COOKIE_MAX_AGE = 60 * 60 * 24 // 1 day
const DEFAULT_COOKIE_PATH = '/'

export const registerSiweRoutes = (
  fastify: FastifyInstance,
  {
    store,
    cookieSameSite = DEFAULT_COOKIE_SAME_SITE,
    cookieMaxAge = DEFAULT_COOKIE_MAX_AGE,
    cookiePath = DEFAULT_COOKIE_PATH,
  }: RegisterSiweRoutesOpts
) => {
  fastify.post(
    '/siwe/init',
    {},
    async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
      void reply.send({
        nonce: await req.siwe.generateNonce(),
      })
    }
  )

  fastify.post(
    '/siwe/signin',
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
      const { signature, message } = req.body

      void req.siwe.setSession(message)

      const authToken = JSON.stringify({
        message,
        signature,
      })

      void reply
        .setCookie('__Host_auth_token', authToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV !== 'development',
          sameSite: cookieSameSite,
          maxAge: cookieMaxAge,
          path: cookiePath,
        })
        .send()
    }
  )

  fastify.get(
    '/siwe/me',
    { preHandler: siweAuthenticated({ store }) },
    async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
      if (!req.siwe.session) {
        return reply.status(401).send()
      }

      void reply.code(200).send({
        loggedIn: true,
        message: req.siwe.session,
      })
    }
  )

  fastify.get(
    '/siwe/signout',
    {},
    async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
      await req.siwe.destroySession()
      void reply.clearCookie('__Host_auth_token').send()
    }
  )

  return fastify
}
