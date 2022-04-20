import type { FastifyPluginAsync } from 'fastify'

import fastifySession from '@fastify/session'
import fastifyCookie from 'fastify-cookie'
import fp from 'fastify-plugin'

import { AuthenticationStorage } from './storage'
import FastifySessionPlugin from '@fastify/session'
import { PrismaClient } from '@prisma/client'

export const AUTH = 'AUTH' as const

export interface FastifySiweOptions {
    secret?: string
    storage?: FastifySessionPlugin.SessionStore
    prismaClient?: PrismaClient
}

export const siwePlugin: FastifyPluginAsync = fp(
  async (fastify, opts: FastifySiweOptions) => {
    fastify.register(fastifyCookie)
    fastify.register(fastifySession, {
      secret: opts.secret ?? '',
      cookie: {
        secure: false,
      },
      store: opts.storage ?? new AuthenticationStorage(opts.prismaClient),
    })
  },
  { name: AUTH },
)

export default siwePlugin
