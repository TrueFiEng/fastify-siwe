import { expect } from 'chai';
import { MockProvider } from 'ethereum-waffle';
import 'jsdom-global/register';
import { SiweMessage } from 'siwe';
import { mock } from './mockApi';

describe('signInWithEthereum', () => {
    const app = mock()
    const provider = new MockProvider({ ganacheOptions: { chain: { chainId: 1 } } as any })
    const signer = provider.getWallets()[0]

    it('returns correct nonce', async () => {
        const { nonce } = (await app.inject({
            method: 'POST',
            url: '/siwe/init',
        })).json()
        expect(nonce).to.match(/^[a-zA-Z0-9_]{17}$/)
    })

    it('authenticates correctly', async () => {
        const { nonce } = (await app.inject({
            method: 'POST',
            url: '/siwe/init',
        })).json()

        const domain = 'https://example.com'
        const origin = 'https://example.com'
        const statement = 'Sign in with Ethereum to the app.';

        const message = new SiweMessage({
            domain,
            address: await signer.getAddress(),
            statement,
            uri: origin,
            version: '1',
            chainId: 1,
            nonce,
        });

        const signature = await signer.signMessage(message.prepareMessage())
        const authToken = JSON.stringify({ signature, message })

        const authResponse = (await app.inject({
            method: 'GET',
            url: '/siwe/me',
            headers: {
                Authorization: `Bearer ${authToken}`,
            },
        })).json()

        expect(authResponse.loggedIn).to.equal(true)
        expect(authResponse.message).to.deep.equal(message)
    })

    it('returns 403 because of invalid nonce', async () => {
        const domain = 'https://example.com'
        const origin = 'https://example.com'
        const statement = 'Sign in with Ethereum to the app.';

        const invalidNonce = '0'.repeat(17)
        const message = new SiweMessage({
            domain,
            address: await signer.getAddress(),
            statement,
            uri: origin,
            version: '1',
            chainId: 1,
            nonce: invalidNonce,
        });

        const signature = await signer.signMessage(message.prepareMessage())
        const authToken = JSON.stringify({ signature, message })

        const authResponse = await app.inject({
            method: 'GET',
            url: '/siwe/me',
            headers: {
                Authorization: `Bearer ${authToken}`,
            },
        })

        expect(authResponse.statusCode).to.equal(403)
        expect(authResponse.payload).to.equal('Invalid nonce')
    })
})
