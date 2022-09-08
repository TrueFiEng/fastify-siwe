import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { Token } from './types'
import { validateToken } from './plugin'

export interface RegisterSiweRoutesOpts {
  cookieSecure?: boolean
  cookieSameSite?: boolean | 'strict' | 'lax' | 'none'
  cookieMaxAge?: number
  cookiePath?: string
}

export const registerSiweRoutes = (
  fastify: FastifyInstance,
  { cookieSecure, cookieSameSite, cookieMaxAge, cookiePath }: RegisterSiweRoutesOpts
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
      if (!signature || !message) {
        return reply.status(422).send({ message: 'Expected prepareMessage object and signature as body.' })
      }
      const { address, chainId } = message
      const token = { signature, message } as Token

      if (signature !== '0x') {
        try {
          await validateToken(token)
          await req.siwe.setMessage(message)
        } catch (err: any) {
          return reply.status(403).send(err.message ?? 'Invalid SIWE token')
        }
      }

      void reply
        .setCookie(`__Host_authToken${address}${chainId}`, JSON.stringify(token), {
          httpOnly: true,
          secure: cookieSecure,
          sameSite: cookieSameSite,
          maxAge: cookieMaxAge,
          path: cookiePath,
        })
        .send()
    }
  )

  fastify.get('/siwe/me', {}, async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
    if (!req.siwe.session) {
      return reply.status(401).send({
        loggedIn: false,
      })
    }

    void reply.code(200).send({
      loggedIn: true,
      message: req.siwe.session,
    })
  })

  fastify.post(
    '/siwe/signout',
    {},
    async function handler(this: FastifyInstance, req: FastifyRequest, reply: FastifyReply) {
      const authorizationHeader = req.headers.authorization
      const [address, chainId] = authorizationHeader?.split(':') ?? []
      if (!chainId || !address) {
        return reply.status(422).send({ message: 'Expected chainId and address as query parameters.' })
      }

      try {
        await req.siwe.destroySession()
      } catch (err) {
        console.error(err)
      }

      void reply
        .clearCookie(`__Host_authToken${address}${chainId}`, {
          secure: cookieSecure,
          sameSite: cookieSameSite,
          path: cookiePath,
        })
        .send()
    }
  )

  return fastify
}
