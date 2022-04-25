import type { PrismaClient } from '@prisma/client'
import type * as Fastify from 'fastify'

import FastifySessionPlugin from '@fastify/session'

export class AuthenticationStorage implements FastifySessionPlugin.SessionStore {
  constructor(
    protected prismaClient: PrismaClient,
  ) {}

  set(sessionId: string, session: Fastify.Session, callback: (err?: Error) => void) {
    this.prismaClient.session.upsert({
      create: {
        id: sessionId,
        data: session as any,
      },
      update: {
        data: session as any,
      },
      where: {
        id: sessionId,
      },
    })
      .then(
        () => callback(),
        err => callback(err),
      )
  }

  get(sessionId: string, callback: (err: Error | null, session: Fastify.Session) => void) {
    this.prismaClient.session.findUnique({
      where: {
        id: sessionId,
      },
    }).then(
      session => {
        if (session) {
          callback(null, session.data as any)
        } else {
          callback(null, undefined as any)
        }
      },
      err => {
        callback(err, undefined as any)
      },
    )
  }

  destroy(sessionId: string, callback: (err?: Error) => void) {
    this.prismaClient.session.delete({
      where: {
        id: sessionId,
      },
    }).then(
      () => callback(),
      err => callback(err),
    )
  }
}
