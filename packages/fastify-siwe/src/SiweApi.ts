import { generateNonce, SiweMessage } from 'siwe'
import { SessionStore } from './index'

export class SiweApi {
  constructor(private readonly _store: SessionStore) {}

  public session?: SiweMessage

  async generateNonce(): Promise<string> {
    const nonce = generateNonce()
    await this._store.save({
      nonce,
    })
    return nonce
  }

  async setMessage(message: SiweMessage): Promise<void> {
    const currentSession = await this._store.get(message.nonce)

    if (!currentSession) {
      throw new Error('Session not initialized')
    }
    if (currentSession.message) {
      throw new Error('Session already exists')
    }

    await this._store.save({
      nonce: message.nonce,
      message,
    })
  }

  async destroySession(): Promise<void> {
    if (!this.session?.nonce) {
      throw new Error('No session to destroy')
    }

    await this._store.remove(this.session.nonce)
    this.session = undefined
  }
}
