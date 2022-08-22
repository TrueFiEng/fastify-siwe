import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { parseAndValidateToken } from './plugin'

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

export const registerSiweRoutes = (fastify: FastifyInstance, opts: RegisterSiweRoutesOpts = defaultOpts) => {
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
      if (!signature || !message) {
        return reply.status(422).send({ message: 'Expected prepareMessage object and signature as body.' })
      }
      const token = JSON.stringify({ signature, message })

      if (signature !== '0x') {
        try {
          await parseAndValidateToken(token)
          await req.siwe.setMessage(message)
        } catch (err: any) {
          return reply.status(403).send(err.message)
        }
      }

      void reply
        .setCookie('__Host_auth_token', token, {
          httpOnly: true,
          secure: opts.cookieSecure,
          sameSite: opts.cookieSameSite,
          maxAge: opts.cookieMaxAge,
          path: opts.cookiePath,
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
      try {
        await req.siwe.destroySession()
      } catch (err) {
        console.error(err)
      }
      void reply.clearCookie('__Host_auth_token').send()
    }
  )

  return fastify
}
