import { InMemoryStore } from '.'
import { SiweApi } from './SiweApi'
import { expect } from 'chai'

describe('SiweApi', () => {
    let store: InMemoryStore
    let siweApi: SiweApi

    beforeEach(async () => {
        store = new InMemoryStore()
        siweApi = new SiweApi(store)
    })

    it('generates correct nonce and saves to store', async () => {
        const nonce = await siweApi.generateNonce()
        expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)

        const session = await store.get(nonce)
        expect(session).to.exist
        expect(session?.nonce).to.equal(nonce)
    })
    
    xit('destroysSession', async () => {
        const nonce = await siweApi.generateNonce()
        const session = await store.get(nonce)
        expect(session).to.exist
        expect(session?.nonce).to.equal(nonce)
        
        console.log(store.sessions)

        // await siweApi.destroySession()
    })
})
