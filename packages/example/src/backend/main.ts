import createFastify from 'fastify'
import { siwePlugin, InMemoryStore, registerSiweRoutes } from 'fastify-siwe'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'

const fastify = createFastify({ logger: true })
const store = new InMemoryStore()

void fastify.register(cors, {
  credentials: true,
  origin: (origin, cb) => {
    const originHostName = new URL(origin).hostname
    const allowedHostName = new URL(process.env.CORS_ORIGIN ?? 'http://localhost:3000').hostname
    if (originHostName === allowedHostName) {
      cb(null, true)
      return
    }
    cb(new Error('Not allowed'), false)
  },
})
void fastify.register(cookie)
void fastify.register(siwePlugin({ store }))
registerSiweRoutes(fastify, { store, cookieSameSite: 'none' })

const start = async () => {
  try {
    const port = parseInt(process.env.PORT ?? '3001', 10)
    const host = process.env.HOST ?? '0.0.0.0'
    await fastify.listen({ port, host })
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
void start()
