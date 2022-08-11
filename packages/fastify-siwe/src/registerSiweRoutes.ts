import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'

export interface RegisterSiweRoutesOpts {
  cookieSecure?: boolean
  cookieSameSite?: boolean | 'strict' | 'lax' | 'none'
  cookieMaxAge?: number
  cookiePath?: string
}

const defaultOpts: RegisterSiweRoutesOpts = {
  cookieSecure: process.env.NODE_ENV !== 'development',
  cookieSameSite: 'strict',
  cookieMaxAge: 60 * 60 * 24, // 1 day
  cookiePath: '/',
}

export const registerSiweRoutes = (fastify: FastifyInstance, opts?: RegisterSiweRoutesOpts) => {
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

      const currentSession = await req.siwe._store.get(message.nonce)

      if (!currentSession) {
        return reply.status(403).send('Session not found')
      }
      if (currentSession?.message) {
        return reply.status(403).send('Session already exists')
      }

      const authToken = JSON.stringify({
        message,
        signature,
      })

      void reply
        .setCookie('__Host_auth_token', authToken, {
          httpOnly: true,
          secure: opts?.cookieSecure ?? defaultOpts.cookieSecure,
          sameSite: opts?.cookieSameSite ?? defaultOpts.cookieSameSite,
          maxAge: opts?.cookieMaxAge ?? defaultOpts.cookieMaxAge,
          path: opts?.cookiePath ?? defaultOpts.cookiePath,
        })
        .send()
    }
  )

  fastify.get('/siwe/me', {}, async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
    if (!req.siwe.session) {
      return reply.status(401).send()
    }

    void reply.code(200).send({
      loggedIn: true,
      message: req.siwe.session,
    })
  })

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
