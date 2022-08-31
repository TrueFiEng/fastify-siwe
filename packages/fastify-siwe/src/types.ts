import type { SiweApi } from './SiweApi'
import type { SiweMessage } from 'siwe'

export type StoredSession = {
  nonce: string
  message?: SiweMessage
}

export interface SessionStore {
  get(nonce: string): Promise<StoredSession | undefined>

  save(session: StoredSession): Promise<void>

  remove(nonce: string): Promise<void>
}

export type Token = { signature: string; message: SiweMessage }
export type TokenSet = Record<number, Record<string, Token>>

declare module 'fastify' {
  interface FastifyRequest {
    siwe: SiweApi
  }
}
