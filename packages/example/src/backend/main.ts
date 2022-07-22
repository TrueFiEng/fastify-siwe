import createFastify from 'fastify'
import { siwePlugin, InMemoryStore, registerSiweRoutes } from 'fastify-siwe'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'

const fastify = createFastify({ logger: true })
const store = new InMemoryStore()

fastify.register(cors, {
  origin: true,
  credentials: true,
})
fastify.register(cookie) // TODO: Comment out, make sure there is understable error message for the user

// register siwe
// add routes
// TODO: Forget one, see what happens. Forget the other, see what happens.

fastify.register(siwePlugin({ store }))
registerSiweRoutes(fastify, { store })

const start = async () => {
  try {
    await fastify.listen({ port: 3001, host: '0.0.0.0' })
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
start()
