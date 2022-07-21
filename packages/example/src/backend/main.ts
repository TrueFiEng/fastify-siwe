import createFastify, { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { signInWithEthereum, InMemoryStore, siweMiddleware } from 'fastify-siwe'
import cors from '@fastify/cors'
import { SiweMessage } from 'siwe'
import cookie from '@fastify/cookie'

const fastify = createFastify({ logger: true })
const store = new InMemoryStore()

fastify.register(cors, {
  origin: true,
  credentials: true,
})
fastify.register(cookie)
fastify.register(signInWithEthereum({ store }))

fastify.post(
  '/siwe/init',
  {},
  async function handler(
    this: FastifyInstance,
    req: FastifyRequest,
    reply: FastifyReply,
  ) {
    reply.send({
      nonce: await req.siwe.generateNonce(),
    })
  },
)

fastify.post(
  '/siwe/cookie',
  {},
  async function handler(
    this: FastifyInstance,
    req: FastifyRequest<{Body: {
      signature: string,
      message: SiweMessage,
    }}>,
    reply: FastifyReply,
  ) {
    const authToken = JSON.stringify({
      message: req.body.message,
      signature: req.body.signature,
    })

    reply.setCookie('authToken', authToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24,
      path: '/',
    }).send()
  },
)


fastify.get(
  '/siwe/me',
  { preHandler: siweMiddleware({ store }) },
  async function handler(
    this: FastifyInstance,
    req: FastifyRequest,
    reply: FastifyReply,
  ) {
    if (!req.siwe.session) {
      reply.status(401).send()
      return
    }

    reply.code(200).send({
      loggedIn: true,
      message: req.siwe.session,
    })
  },
)

fastify.get(
  '/siwe/signout',
  {},
  async function handler(
    this: FastifyInstance,
    req: FastifyRequest,
    reply: FastifyReply,
  ) {
    reply.clearCookie('authToken').send({
      loggedIn: false,
    })
  },
)

const start = async () => {
  try {
    await fastify.listen({ port: 3001, host: '0.0.0.0' })
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
start()
