import { Wallet } from 'ethers'
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { FastifyInstance, LightMyRequestResponse } from 'fastify'
import { SiweMessage } from 'siwe'

export async function getNonce(app: FastifyInstance) {
  return app.inject({ method: 'POST', url: '/siwe/init', validate: true })
}

export async function signIn(
  app: FastifyInstance,
  { signature, message }: { signature: string; message: SiweMessage }
) {
  return app.inject({ method: 'POST', url: '/siwe/signin', payload: { signature, message }, validate: true })
}

export async function getAuth(app: FastifyInstance, token: string) {
  return app.inject({
    method: 'GET',
    url: '/siwe/me',
    validate: true,
    cookies: {
      __Host_auth_token: token,
    },
  })
}

export function createAuthMessage(wallet: Wallet) {
  return {
    domain: 'localhost:3001',
    address: wallet.address,
    statement: 'Sign in with Ethereum to the app.',
    uri: 'http://localhost:3001',
    version: '1',
    chainId: 1,
  }
}

export async function authenticate(wallet: Wallet, app: FastifyInstance) {
  const nonceResponse = await getNonce(app)
  const nonceResponseBody = JSON.parse(nonceResponse.body)
  const message = createAuthMessage(wallet)

  const siweMessage = new SiweMessage({
    ...message,
    nonce: nonceResponseBody.nonce,
  })

  const signature = await wallet.signMessage(siweMessage.prepareMessage())
  const token = JSON.stringify({ signature, message: siweMessage })

  await getAuth(app, token)
  return token
}
