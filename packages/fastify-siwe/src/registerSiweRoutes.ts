import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { SiweMessage } from 'siwe'
import { Token, TokenSet } from './types'
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
      let tokenSet: TokenSet = {}
      try {
        tokenSet = JSON.parse(req.cookies['__Host_token_set'] ?? '{}') as TokenSet
      } catch (err) {
        console.error(err)
      }

      const { signature, message } = req.body
      if (!signature || !message) {
        return reply.status(422).send({ message: 'Expected prepareMessage object and signature as body.' })
      }
      const chainId = message.chainId
      const address = message.address
      const token = { signature, message } as Token

      if (signature !== '0x') {
        try {
          await validateToken(token)
          await req.siwe.setMessage(message)
        } catch (err: any) {
          return reply.status(403).send(err.message ?? 'Invalid SIWE token')
        }
      }

      const newTokenSet = { ...tokenSet, [chainId]: { ...tokenSet[chainId], [address]: token } }

      void reply
        .setCookie('__Host_token_set', JSON.stringify(newTokenSet), {
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
    async function handler(
      this: FastifyInstance,
      req: FastifyRequest<{
        Querystring: {
          chainId?: number
          address?: string
        }
      }>,
      reply: FastifyReply
    ) {
      const { chainId, address } = req.query
      if (!chainId || !address) {
        return reply.status(422).send({ message: 'Expected chainId and address as query parameters.' })
      }

      let tokenSet: TokenSet = {}
      try {
        tokenSet = JSON.parse(req.cookies['__Host_token_set'] ?? '{}')
        await req.siwe.destroySession()
      } catch (err) {
        console.error(err)
      }

      delete tokenSet[chainId][address]
      void reply
        .setCookie('__Host_token_set', JSON.stringify(tokenSet), {
          httpOnly: true,
          secure: cookieSecure,
          sameSite: cookieSameSite,
          maxAge: cookieMaxAge,
          path: cookiePath,
        })
        .send()
    }
  )

  return fastify
}
