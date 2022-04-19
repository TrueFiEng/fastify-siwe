import type { FastifyInstance, FastifyRequest } from 'fastify'

import { generateNonce, SiweMessage } from 'siwe'

declare module 'fastify' {
  interface Session {
    address?: string,
    nonce?: string,
  }
}

export default async function authRoutes(fastify: FastifyInstance) {
  fastify.get(
    '/auth/siwe/nonce',
    { },
    async function handler(
      this: FastifyInstance,
      req: FastifyRequest,
      reply,
    ) {
      const nonce = generateNonce()
      req.session.nonce = nonce
      await req.session.save()

      reply.send({ nonce })
    },
  )

  fastify.post(
    '/auth/siwe/login',
    { },
    async function handler(
      this: FastifyInstance,
      req: FastifyRequest<{ Body: { message: string, signature: string } }>,
      reply,
    ) {
      try {
        const { message, signature } = req.body
        const siweMessage = new SiweMessage(message)

        await siweMessage.validate(signature)

        if (siweMessage.nonce !== req.session.nonce) {
          reply.status(403).send('invalid nonce')
          return
        }

        req.session.address = siweMessage.address
        await req.session.save()

        reply.code(200).send({
          sessionId: req.session.sessionId,
          address: req.session.address,
        })
      } catch (err) {
        console.log(err)
        reply.status(401).send()
      }
    },
  )

  fastify.get(
    '/auth/me',
    { },
    async function handler(
      this: FastifyInstance,
      req: FastifyRequest,
      reply,
    ) {
      await req.session.save()
      reply.send({
        sessionId: req.session.sessionId,
        address: req.session.address,
      })
    },
  )

  fastify.post(
    '/logout/me',
    { },
    async function handler(
      this: FastifyInstance,
      req: FastifyRequest,
      reply,
    ) {
      await req.session.destroy()
      reply.status(200).send()
    },
  )
}
