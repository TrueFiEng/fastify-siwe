import { Wallet } from 'ethers'
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { FastifyInstance, LightMyRequestResponse } from 'fastify'
import { SiweMessage } from 'siwe'

export type UserInfo = {
  chainId: number
  address: string
}

export async function getNonce(app: FastifyInstance) {
  return app.inject({ method: 'POST', url: '/siwe/init', validate: true })
}

export async function signIn(
  app: FastifyInstance,
  { signature, message }: { signature: string; message: SiweMessage }
) {
  return app.inject({ method: 'POST', url: '/siwe/signin', payload: { signature, message }, validate: true })
}

export async function signOut(app: FastifyInstance, token: string, { chainId, address }: UserInfo) {
  return app.inject({
    method: 'POST',
    url: '/siwe/signout',
    validate: true,
    cookies: {
      [`__Host_authToken${address}${chainId}`]: token,
    },
    headers: {
      multichain: `${address}:${chainId}`,
    },
  })
}

export async function getAuth(app: FastifyInstance, token: string, { chainId, address }: UserInfo) {
  return app.inject({
    method: 'GET',
    url: '/siwe/me',
    validate: true,
    cookies: {
      [`__Host_authToken${address}${chainId}`]: token,
    },
    headers: {
      multichain: `${address}:${chainId}`,
    },
  })
}

export async function createAuthMessage(wallet: Wallet) {
  return {
    domain: 'localhost:3001',
    address: wallet.address,
    statement: 'Sign in with Ethereum to the app.',
    uri: 'http://localhost:3001',
    version: '1',
    chainId: await wallet.getChainId(),
  }
}

export async function authenticate(wallet: Wallet, app: FastifyInstance) {
  const { nonce } = JSON.parse((await getNonce(app)).payload)
  const defaultMessage = await createAuthMessage(wallet)

  const message = new SiweMessage({
    ...defaultMessage,
    nonce,
  })

  const signature = await wallet.signMessage(message.prepareMessage())
  await signIn(app, { signature, message })

  const token = JSON.stringify({ signature, message: message })
  await getAuth(app, token, { chainId: await wallet.getChainId(), address: wallet.address })
  return token
}
