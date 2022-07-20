import { expect } from 'chai'
import { mock } from './mockApi'

describe('signInWithEthereum', () => {
    const app = mock()

    it('returns correct nonce', async () => {
        const response = await app.inject({
            method: 'POST',
            url: '/siwe/init',
        })
        const { nonce } = await response.json()
        expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)
    })
})
