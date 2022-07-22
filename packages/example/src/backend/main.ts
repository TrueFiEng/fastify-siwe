import createFastify from 'fastify'
import { siwePlugin, InMemoryStore, registerSiweRoutes } from 'fastify-siwe'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'

const fastify = createFastify({ logger: true })
const store = new InMemoryStore()

void fastify.register(cors, {
  credentials: true,
  origin: (origin, cb) => {
    const hostname = new URL(origin).hostname
    if (hostname === 'localhost') {
      cb(null, true)
      return
    }
    cb(new Error('Not allowed'), false)
  },
})
void fastify.register(cookie)
void fastify.register(siwePlugin({ store }))
registerSiweRoutes(fastify, { store })

const start = async () => {
  try {
    await fastify.listen({ port: 3001, host: '0.0.0.0' })
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
void start()
