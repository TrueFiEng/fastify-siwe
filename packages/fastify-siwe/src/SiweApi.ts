import { generateNonce, SiweMessage } from 'siwe'
import { SessionStore, StoredSession } from './index'

export class SiweApi {
  constructor(public readonly _store: SessionStore) {}

  public session?: SiweMessage

  async generateNonce(): Promise<string> {
    const nonce = generateNonce()
    return nonce
  }

  async setSession(session: StoredSession) {
    await this._store.save(session)
    this.session = session.message
  }

  async destroySession(): Promise<void> {
    if (!this.session?.nonce) {
      throw new Error('No session to destroy')
    }

    await this._store.remove(this.session.nonce)
    this.session = undefined
  }
}
