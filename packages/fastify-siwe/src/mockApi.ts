import createFastify, { FastifyInstance, FastifyRequest } from 'fastify'
import { signInWithEthereum } from '.'

export const mock = (opts = {}) => {
  const fastify = createFastify(opts)

  fastify.register(signInWithEthereum())

  fastify.post('/siwe/init', {}, async function handler(this: FastifyInstance, req: FastifyRequest, reply) {
    reply.send({
      nonce: await req.siwe.generateNonce(),
    })
  })

  fastify.get('/siwe/me', {}, async function handler(this: FastifyInstance, req: FastifyRequest, reply) {
    if (!req.siwe.session) {
      reply.status(401).send()
      return
    }

    reply.code(200).send({
      loggedIn: true,
      message: req.siwe.session,
    })
  })

  return fastify
}
